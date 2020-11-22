#include "NativeLoaderHelper.h"

namespace ds_mmap
{
    namespace ds_process
    {
        CNtLdr::CNtLdr(CMemCore& memory)
            : m_memory(memory)
            , m_LdrpHashTable(0)
            , m_LdrpModuleIndexBase(0)
            , m_LdrpModuleBase(0)
            , m_LdrHeapBase(0)
            , m_LdrpHandleTlsData(nullptr)
            , m_RtlInsertInvertedFunctionTable(nullptr)
            , m_LdrpInvertedFunctionTable(nullptr)
        {
            memset(&m_verinfo, 0x0, sizeof(m_verinfo));
        }

        CNtLdr::~CNtLdr(void)
        {
        }

        bool CNtLdr::Init()
        {
            m_verinfo.dwOSVersionInfoSize = sizeof(m_verinfo);

            GetVersionEx(&m_verinfo);

            FindLdrpHashTable();
            FindLdrpModuleIndexBase();
            FindLdrpModuleBase();
            PatternSearch();
            FindLdrHeap();

            return true;
        }

        bool CNtLdr::CreateNTReference( HMODULE hMod, size_t ImageSize, const std::wstring& DllBaseName, const std::wstring& DllBasePath )
        {
            if(IsWin8orHigher())
            {
                ULONG hash = 0;
                _LDR_DATA_TABLE_ENTRY_W8 *pEntry = InitW8Node((void*)hMod, ImageSize, DllBaseName, DllBasePath, hash);
                m_nodeMap.emplace(std::make_pair(hMod, pEntry));

                InsertHashNode((PLIST_ENTRY)GET_FIELD_PTR(pEntry, HashLinks), hash);

                _LDR_DATA_TABLE_ENTRY_W8 *pLdrNode = CONTAINING_RECORD(m_LdrpModuleIndexBase, _LDR_DATA_TABLE_ENTRY_W8, BaseAddressIndexNode);
                _LDR_DATA_TABLE_ENTRY_W8 LdrNode   = m_memory.Read<_LDR_DATA_TABLE_ENTRY_W8>(pLdrNode);

                for(;;)
                {
                    if(hMod < LdrNode.DllBase)
                    {
                        if(LdrNode.BaseAddressIndexNode.Left)
                        {
                            pLdrNode = CONTAINING_RECORD(LdrNode.BaseAddressIndexNode.Left, _LDR_DATA_TABLE_ENTRY_W8, BaseAddressIndexNode);
                            m_memory.Read(pLdrNode, sizeof(LdrNode), &LdrNode);
                        }
                        else
                        {
                            InsertTreeNode(pLdrNode, pEntry, true);
                            return true;
                        }
                    }
                    else if(hMod > LdrNode.DllBase)
                    {
                        if(LdrNode.BaseAddressIndexNode.Right)
                        {
                            pLdrNode = CONTAINING_RECORD(LdrNode.BaseAddressIndexNode.Right, _LDR_DATA_TABLE_ENTRY_W8, BaseAddressIndexNode);
                            m_memory.Read(pLdrNode, sizeof(LdrNode), &LdrNode);
                        }
                        else
                        {
                            InsertTreeNode(pLdrNode, pEntry, false);
                            return true;
                        }
                    }
                    else if(hMod == LdrNode.DllBase)
                    {
                        _LDR_DDAG_NODE Ddag = m_memory.Read<_LDR_DDAG_NODE>(LdrNode.DdagNode);

                        Ddag.ReferenceCount++;

                        m_memory.Write<_LDR_DDAG_NODE>(LdrNode.DdagNode, Ddag);

                        return true;
                    }
                    else
                        return false;
                }
            }
            else
            {
                ULONG hash = 0;
                _LDR_DATA_TABLE_ENTRY_W7 *pEntry = InitW7Node((void*)hMod, ImageSize, DllBaseName, DllBasePath, hash);
                m_nodeMap.emplace(std::make_pair(hMod, pEntry));

                InsertHashNode((PLIST_ENTRY)GET_FIELD_PTR(pEntry, HashLinks), hash);

                InsertMemModuleNode((PLIST_ENTRY)GET_FIELD_PTR(pEntry, InMemoryOrderLinks), 
                                    (PLIST_ENTRY)GET_FIELD_PTR(pEntry, InLoadOrderLinks));
			}

            return false;
        }

        template<typename T> 
        T* CNtLdr::SetNode( T* ptr, void* pModule )
        {
            if(ptr == nullptr)
            {
                /*AsmJit::Assembler a;
                AsmJitHelper ah(a);

                ah.GenPrologue();
                ah.GenCall(&GetProcessHeap, {  });
                ah.GenCall(&HeapAlloc, { AsmJit::nax, HEAP_ZERO_MEMORY, sizeof(T) });
                ah.SaveRetValAndSignalEvent();
                ah.GenEpilogue();

                m_memory.ExecInWorkerThread(a.make(), a.getCodeSize(), (size_t&)ptr);  */
                //if(ptr != nullptr)
                if(m_memory.Allocate(sizeof(T), (void*&)ptr) == ERROR_SUCCESS)
                    m_memory.Write<void*>(GET_FIELD_PTR(ptr, DllBase), pModule);
            }

            return ptr;
        }

        bool CNtLdr::AddStaticTLSEntry( void* pModule )
        {
            void* pNode = m_nodeMap.count((HMODULE)pModule) ? m_nodeMap[(HMODULE)pModule] : nullptr;

            if((pNode = SetNode((LDR_DATA_TABLE_ENTRY*)pNode, pModule)) == nullptr)
                return false;

            if(m_LdrpHandleTlsData)
            {
                AsmJit::Assembler a;
                AsmJitHelper ah(a);
                size_t result = 0;

                ah.GenPrologue();
                ah.GenCall(m_LdrpHandleTlsData, { (size_t)pNode });
                ah.SaveRetValAndSignalEvent();
                ah.GenEpilogue();

                m_memory.ExecInWorkerThread(a.make(), a.getCodeSize(), result);  
            }
            else
                return false;

            return true;
        }

        bool CNtLdr::InsertInvertedFunctionTable( void* ModuleBase, size_t ImageSize )
        { 
            RTL_INVERTED_FUNCTION_TABLE7 table = {0};
            PRTL_INVERTED_FUNCTION_TABLE_ENTRY Entries = nullptr;
            AsmJit::Assembler a;
            AsmJitHelper ah(a);
            size_t result = 0;

            if(m_RtlInsertInvertedFunctionTable == nullptr || m_LdrpInvertedFunctionTable == 0)
                return false;

            if(IsWin8orHigher())
                Entries = (PRTL_INVERTED_FUNCTION_TABLE_ENTRY)GET_FIELD_PTR((RTL_INVERTED_FUNCTION_TABLE8*)&table, Entries);
            else
                Entries = (PRTL_INVERTED_FUNCTION_TABLE_ENTRY)GET_FIELD_PTR(&table, Entries);

            m_memory.Read(m_LdrpInvertedFunctionTable, sizeof(table), &table);
            for(DWORD i = 0; i < table.Count; i++)
                if(Entries[i].ImageBase == ModuleBase)
                    return true;

            ah.GenPrologue();

            if(IsWin8orHigher())
                ah.GenCall(m_RtlInsertInvertedFunctionTable, { (size_t)ModuleBase, ImageSize });
            else
                ah.GenCall(m_RtlInsertInvertedFunctionTable, { (size_t)m_LdrpInvertedFunctionTable, (size_t)ModuleBase, ImageSize });

            ah.SaveRetValAndSignalEvent();
            ah.GenEpilogue();

            m_memory.ExecInWorkerThread(a.make(), a.getCodeSize(), result);            
            m_memory.Read(m_LdrpInvertedFunctionTable, sizeof(table), &table);

            for(DWORD i = 0; i < table.Count; i++)
            {
                if(Entries[i].ImageBase == ModuleBase)
                {
                    if(Entries[i].ExceptionDirectorySize != 0)
                        return true;

                    PIMAGE_RUNTIME_FUNCTION_ENTRY pImgEntry = nullptr;

                    m_memory.Allocate(sizeof(DWORD)*0x100, (PVOID&)pImgEntry);

                    // m_LdrpInvertedFunctionTable->Entries[i].ExceptionDirectory
                    size_t field_ofst = (size_t)&Entries[i].ExceptionDirectory - (size_t)&table;

                    return (m_memory.Write((size_t)m_LdrpInvertedFunctionTable + field_ofst, RtlEncodeSystemPointer(pImgEntry)) == ERROR_SUCCESS);
                }
            }

            return false;
        }

        _LDR_DATA_TABLE_ENTRY_W8* CNtLdr::InitW8Node( void* ModuleBase, size_t ImageSize, const std::wstring& dllname, const std::wstring& dllpath, ULONG& outHash )
        {
            void *StringBuf         = nullptr;
            UNICODE_STRING strLocal = {0};
            size_t result           = 0;

            _LDR_DATA_TABLE_ENTRY_W8 *pEntry = nullptr; 
            _LDR_DDAG_NODE *pDdagNode = nullptr;

            AsmJit::Assembler a;
            AsmJitHelper ah(a);

            m_memory.Allocate(0x1000, StringBuf);

            ah.GenPrologue();
            ah.GenCall(&HeapAlloc, { m_LdrHeapBase, HEAP_ZERO_MEMORY, sizeof(_LDR_DATA_TABLE_ENTRY_W8) });

            ah.SaveRetValAndSignalEvent();
            ah.GenEpilogue();

            m_memory.ExecInWorkerThread(a.make(), a.getCodeSize(), result);
            pEntry = (_LDR_DATA_TABLE_ENTRY_W8*)result;

            if(pEntry)
            {
                a.clear();

                ah.GenPrologue();

                ah.GenCall(&HeapAlloc, { m_LdrHeapBase, HEAP_ZERO_MEMORY, sizeof(_LDR_DDAG_NODE) });

                ah.SaveRetValAndSignalEvent();
                ah.GenEpilogue();

                m_memory.ExecInWorkerThread(a.make(), a.getCodeSize(), result);
                pDdagNode = (_LDR_DDAG_NODE*)result;

                if(pDdagNode)
                {
                    // pEntry->DllBase = ModuleBase;
                    m_memory.Write<void*>(GET_FIELD_PTR(pEntry, DllBase), ModuleBase);

                    // pEntry->SizeOfImage = ImageSize;
                    m_memory.Write<ULONG>(GET_FIELD_PTR(pEntry, SizeOfImage), (ULONG)ImageSize);

                    RtlInitUnicodeString(&strLocal, dllname.c_str());
                    RtlHashUnicodeString(&strLocal, TRUE, 0, &outHash);

                    strLocal.Buffer = (PWSTR)StringBuf;
                    m_memory.Write((uint8_t*)StringBuf, dllname.length() * sizeof(wchar_t) + 2, (void*)dllname.c_str());

                    // pEntry->BaseDllName = strLocal;
                    m_memory.Write<UNICODE_STRING>(GET_FIELD_PTR(pEntry, BaseDllName), strLocal);

                    RtlInitUnicodeString(&strLocal, dllpath.c_str());
                    strLocal.Buffer = (PWSTR)((uint8_t*)StringBuf + 0x800);
                    m_memory.Write((uint8_t*)StringBuf + 0x800, dllpath.length() * sizeof(wchar_t) + 2, (void*)dllpath.c_str());
              
                    // pEntry->FullDllName = strLocal;
                    m_memory.Write<UNICODE_STRING>(GET_FIELD_PTR(pEntry, FullDllName), strLocal);

                    // pEntry->BaseNameHashValue = hash;
                    m_memory.Write<ULONG>(GET_FIELD_PTR(pEntry, BaseNameHashValue), outHash);

                    // pEntry->DdagNode = pDdagNode;
                    m_memory.Write<_LDR_DDAG_NODE*>(GET_FIELD_PTR(pEntry, DdagNode), pDdagNode);

                    // pDdagNode->State = LdrModulesReadyToRun;
                    m_memory.Write<enum _LDR_DDAG_STATE>(GET_FIELD_PTR(pDdagNode, State), LdrModulesReadyToRun);

                    // pDdagNode->ReferenceCount = 1;
                    m_memory.Write<ULONG>(GET_FIELD_PTR(pDdagNode, ReferenceCount), 1);

                    // pDdagNode->LoadCount = -1;
                    m_memory.Write<LONG>(GET_FIELD_PTR(pDdagNode, LoadCount), -1);

                    return pEntry;
                }

                return nullptr;
            }

            return nullptr;
        }

        _LDR_DATA_TABLE_ENTRY_W7* CNtLdr::InitW7Node( void* ModuleBase, size_t ImageSize, const std::wstring& dllname, const std::wstring& dllpath, ULONG& outHash )
        {
            void *StringBuf         = nullptr;
            UNICODE_STRING strLocal = {0};
            size_t result           = 0;

            _LDR_DATA_TABLE_ENTRY_W7 *pEntry = nullptr; 

            AsmJit::Assembler a;
            AsmJitHelper ah(a);

            m_memory.Allocate(MAX_PATH, StringBuf);

            ah.GenPrologue();

            ah.GenCall(&HeapAlloc, {m_LdrHeapBase, HEAP_ZERO_MEMORY, sizeof(_LDR_DATA_TABLE_ENTRY_W7)});

            ah.SaveRetValAndSignalEvent();
            ah.GenEpilogue();

            m_memory.ExecInWorkerThread(a.make(), a.getCodeSize(), result);
            pEntry = (_LDR_DATA_TABLE_ENTRY_W7*)result;

            if(pEntry)
            {
                // pEntry->DllBase = ModuleBase;
                m_memory.Write<void*>(GET_FIELD_PTR(pEntry, DllBase), ModuleBase);

                // pEntry->SizeOfImage = ImageSize;
                m_memory.Write<ULONG>(GET_FIELD_PTR(pEntry, SizeOfImage), (ULONG)ImageSize);

                // pEntry->LoadCount = -1;
                m_memory.Write<short>(GET_FIELD_PTR(pEntry, LoadCount), -1);

                RtlInitUnicodeString(&strLocal, dllname.c_str());

                outHash = 0;
                for(auto& chr : dllname)
                    outHash += 0x1003F * (unsigned short)RtlUpcaseUnicodeChar(chr);

                strLocal.Buffer = (PWSTR)StringBuf;
                m_memory.Write((uint8_t*)StringBuf, dllname.length() * sizeof(wchar_t) + 2, (void*)dllname.c_str());

                // pEntry->BaseDllName = strLocal;
                m_memory.Write<UNICODE_STRING>(GET_FIELD_PTR(pEntry, BaseDllName), strLocal);

                RtlInitUnicodeString(&strLocal, dllpath.c_str());
                strLocal.Buffer = (PWSTR)((uint8_t*)StringBuf + 0x800);
                m_memory.Write((uint8_t*)StringBuf + 0x800, dllpath.length() * sizeof(wchar_t) + 2, (void*)dllpath.c_str());

                // pEntry->FullDllName = strLocal;
                m_memory.Write<UNICODE_STRING>(GET_FIELD_PTR(pEntry, FullDllName), strLocal);

                return pEntry;
            }

            return nullptr;
        }

        void CNtLdr::InsertTreeNode( _LDR_DATA_TABLE_ENTRY_W8* pParentNode, _LDR_DATA_TABLE_ENTRY_W8* pNode, bool bLeft /*= false */ )
        {
            // pNode->BaseAddressIndexNode.ParentValue = (ULONG)&pParentNode->BaseAddressIndexNode;
            m_memory.Write<void*>(GET_FIELD_PTR(pNode, BaseAddressIndexNode.ParentValue), GET_FIELD_PTR(pParentNode, BaseAddressIndexNode));

            if(bLeft)
                // pParentNode->BaseAddressIndexNode.Left  = (_RTL_BALANCED_NODE*)(&pNode->BaseAddressIndexNode);
                m_memory.Write<void*>(GET_FIELD_PTR(pParentNode, BaseAddressIndexNode.Left), GET_FIELD_PTR(pNode, BaseAddressIndexNode));
                    
            else
                // pParentNode->BaseAddressIndexNode.Right = (_RTL_BALANCED_NODE*)(&pNode->BaseAddressIndexNode);
                m_memory.Write<void*>(GET_FIELD_PTR(pParentNode, BaseAddressIndexNode.Right), GET_FIELD_PTR(pNode, BaseAddressIndexNode));
        }

		void CNtLdr::InsertMemModuleNode( PLIST_ENTRY pNodeMemoryOrderLink, PLIST_ENTRY pNodeLoadOrderLink )
		{
            PPEB pPeb = m_memory.GetPebBase();

            if(pPeb)
            {
                PPEB_LDR_DATA pLdr = m_memory.Read<PPEB_LDR_DATA>(GET_FIELD_PTR(pPeb, Ldr));
                
                if(pLdr)
                    InsertTailList((PLIST_ENTRY)GET_FIELD_PTR(pLdr, InMemoryOrderModuleList), pNodeMemoryOrderLink);

                PLIST_ENTRY pModuleList = m_memory.Read<PLIST_ENTRY>(m_LdrpModuleBase);

                if(pModuleList)
                    InsertTailList(pModuleList, pNodeLoadOrderLink);
            }
        }

        void CNtLdr::InsertHashNode( PLIST_ENTRY pNodeLink, ULONG hash )
        {
            if(pNodeLink)
            {
                PLIST_ENTRY pHashList = m_memory.Read<PLIST_ENTRY>(m_LdrpHashTable + sizeof(LIST_ENTRY)*(hash & 0x1F));

                InsertTailList(pHashList, pNodeLink);
            }
        }

        VOID CNtLdr::InsertTailList(PLIST_ENTRY ListHead, PLIST_ENTRY Entry)
        {
            PLIST_ENTRY PrevEntry;

            //PrevEntry = ListHead->Blink;
            PrevEntry = m_memory.Read<PLIST_ENTRY>(GET_FIELD_PTR(ListHead, Blink));

            //Entry->Flink = ListHead;
            //Entry->Blink = PrevEntry;
            m_memory.Write<PLIST_ENTRY>(GET_FIELD_PTR(Entry, Flink), ListHead);
            m_memory.Write<PLIST_ENTRY>(GET_FIELD_PTR(Entry, Blink), PrevEntry);

            //PrevEntry->Flink = Entry;
            //ListHead->Blink  = Entry;
            m_memory.Write<PLIST_ENTRY>(GET_FIELD_PTR(PrevEntry, Flink), Entry);
            m_memory.Write<PLIST_ENTRY>(GET_FIELD_PTR(ListHead,  Blink), Entry);
        }

        bool CNtLdr::FindLdrpHashTable()
        {
            _PEB_LDR_DATA_W8 *Ldr = (_PEB_LDR_DATA_W8*)NtCurrentTeb()->ProcessEnvironmentBlock->Ldr;
            ULONG NtdllHashIndex  = 0;

            if(IsWin8orHigher())
            {
                _LDR_DATA_TABLE_ENTRY_W8 *Ntdll = CONTAINING_RECORD (Ldr->InInitializationOrderModuleList.Flink, _LDR_DATA_TABLE_ENTRY_W8, InInitializationOrderLinks);

                RtlHashUnicodeString(&Ntdll->BaseDllName, TRUE, 0, &NtdllHashIndex);
                NtdllHashIndex &= 0x1F;

                ULONG_PTR NtdllBase = (ULONG_PTR) Ntdll->DllBase;
                ULONG_PTR NtdllEndAddress = NtdllBase + Ntdll->SizeOfImage - 1;

                bool bHeadFound = false;
                PLIST_ENTRY pNtdllHashHead = NULL;

                for (PLIST_ENTRY e = Ntdll->HashLinks.Flink; e != &Ntdll->HashLinks; e = e->Flink)
                {
                    if ((ULONG_PTR)e >= NtdllBase && (ULONG_PTR)e < NtdllEndAddress)
                    {
                        bHeadFound = true;
                        pNtdllHashHead = e;
                        break;
                    }
                }

                if (bHeadFound)
                {
                    m_LdrpHashTable = (size_t)(pNtdllHashHead - NtdllHashIndex);
                }

                return bHeadFound;
            }
            else
            {
                _LDR_DATA_TABLE_ENTRY_W7 *Ntdll = CONTAINING_RECORD (Ldr->InInitializationOrderModuleList.Flink, _LDR_DATA_TABLE_ENTRY_W7, InInitializationOrderLinks);
                std::wstring name = Ntdll->BaseDllName.Buffer;
                
                for(auto& ch : name)
                    NtdllHashIndex += 0x1003F * (unsigned short)RtlUpcaseUnicodeChar(ch);

                NtdllHashIndex &= 0x1F;

                ULONG_PTR NtdllBase = (ULONG_PTR) Ntdll->DllBase;
                ULONG_PTR NtdllEndAddress = NtdllBase + Ntdll->SizeOfImage - 1;

                bool bHeadFound = false;
                PLIST_ENTRY pNtdllHashHead = NULL;

                for (PLIST_ENTRY e = Ntdll->HashLinks.Flink; e != &Ntdll->HashLinks; e = e->Flink)
                {
                    if ((ULONG_PTR)e >= NtdllBase && (ULONG_PTR)e < NtdllEndAddress)
                    {
                        bHeadFound = true;
                        pNtdllHashHead = e;
                        break;
                    }
                }

                if (bHeadFound)
                {
                    m_LdrpHashTable = (size_t)(pNtdllHashHead - NtdllHashIndex);
                }

                return bHeadFound;
            }  
        }

        bool CNtLdr::FindLdrpModuleIndexBase()
        {
            PPEB pPeb = m_memory.GetPebBase();

            if(pPeb)
            {
                size_t lastNode = 0;

                _PEB_LDR_DATA_W8 Ldr            = m_memory.Read<_PEB_LDR_DATA_W8>(m_memory.Read<size_t>(GET_FIELD_PTR(pPeb, Ldr)));
                _LDR_DATA_TABLE_ENTRY_W8 *Ntdll = CONTAINING_RECORD (Ldr.InInitializationOrderModuleList.Flink, _LDR_DATA_TABLE_ENTRY_W8, InInitializationOrderLinks);
                _RTL_BALANCED_NODE pNode        = m_memory.Read<_RTL_BALANCED_NODE>(GET_FIELD_PTR(Ntdll, BaseAddressIndexNode));

                for(; pNode.ParentValue; )
                {
                    lastNode = pNode.ParentValue & (size_t)-8;
                    pNode = m_memory.Read<_RTL_BALANCED_NODE>(lastNode);
                }

                m_LdrpModuleIndexBase = lastNode;

                return true;
            }

            return false;
        }

        /*
            Get PEB->Ldr->InLoadOrderModuleList address
        */
        bool CNtLdr::FindLdrpModuleBase()
        {
            PPEB pPEB = m_memory.GetPebBase();
            PEB  peb  = m_memory.Read<PEB>(pPEB);

            m_LdrpModuleBase = (size_t)peb.Ldr + FIELD_OFFSET(_PEB_LDR_DATA_W8, InLoadOrderModuleList);

            return true;
        }

        bool CNtLdr::PatternSearch()
        {
            std::vector<size_t> foundData;
            ds_pe::CPEManger ntdll;
            void* pStart    = nullptr;
            size_t scanSize = 0;

            ntdll.Parse(GetModuleHandle(_T("ntdll.dll")), false);

            for(auto& section : ntdll.Sections())
            {
                if(_stricmp((LPCSTR)section.Name, ".text") == 0)
                {
                    pStart   = (void*)((size_t)GetModuleHandle(_T("ntdll.dll")) + section.VirtualAddress);
                    scanSize = section.Misc.VirtualSize;

                    break;
                }
            }

            if(pStart == nullptr)
                return false;

            if(IsWin8orHigher())
            {
            #ifdef _M_AMD64
                // LdrpHandleTlsData
                // 48 8B 79 30 45 8D 66 01
                m_memory.FindPattern("\x48\x8b\x79\x30\x45\x8d\x66\x01", "xxxxxxxx", pStart, scanSize, foundData);

                if(!foundData.empty())
                    m_LdrpHandleTlsData = (void*)(foundData.front() - 0x49);
            #else
                // RtlInsertInvertedFunctionTable
                // 8B FF 55 8B EC 51 51 53 57 8B 7D 08 8D
                m_memory.FindPattern("\x8b\xff\x55\x8b\xec\x51\x51\x53\x57\x8b\x7d\x08\x8d", "xxxxxxxxxxxxx", pStart, scanSize, foundData);

                if(!foundData.empty())
                {
                    m_RtlInsertInvertedFunctionTable = (void*)foundData.front();
                    m_LdrpInvertedFunctionTable      = (*(void**)((size_t)m_RtlInsertInvertedFunctionTable + 0x26));
                }

                // LdrpHandleTlsData
                // 8B 45 08 89 45 A0
                m_memory.FindPattern("\x8b\x45\x08\x89\x45\xa0", "xxxxxx", pStart, scanSize, foundData);

                if(!foundData.empty())
                    m_LdrpHandleTlsData = (void*)(foundData.front() - 0xC);
                 
            #endif

            }
            else
            {
            #ifdef _M_AMD64
                // LdrpHandleTlsData
                // 41 B8 09 00 00 00 48 8D 44 24 38
                m_memory.FindPattern(std::string("\x41\xb8\x09\x00\x00\x00\x48\x8d\x44\x24\x38", 11), "xxxxxxxxxxx", pStart, scanSize, foundData);

                if(!foundData.empty())
                    m_LdrpHandleTlsData = (void*)(foundData.front() - 0x27);              
            #else
                // RtlInsertInvertedFunctionTable
                // 8B FF 55 8B EC 56 68
                m_memory.FindPattern("\x8b\xff\x55\x8b\xec\x56\x68", "xxxxxxx", pStart, scanSize, foundData);

                if(!foundData.empty())
                    m_RtlInsertInvertedFunctionTable = (void*)foundData.front();

                // RtlLookupFunctionTable + 0x11
                // 89 5D E0 38
                m_memory.FindPattern("\x89\x5D\xE0\x38", "xxxx", pStart, scanSize, foundData);
                
                if(!foundData.empty())
                    m_LdrpInvertedFunctionTable = (*(void**)(foundData.front() + 0x1B));

                // LdrpHandleTlsData
                // 74 20 8D 45 D4 50 6A 09 
                m_memory.FindPattern("\x74\x20\x8d\x45\xd4\x50\x6a\x09", "xxxxxxxx", pStart, scanSize, foundData);

                if(!foundData.empty())
                    m_LdrpHandleTlsData = (void*)(foundData.front() - 0x14);

            #endif
            }

            return true;
        }

        bool CNtLdr::FindLdrHeap()
        {
            PPEB pPeb = m_memory.GetPebBase();
            MEMORY_BASIC_INFORMATION mbi = {0};

            if(pPeb)
            {
                PEB_LDR_DATA          Ldr        = m_memory.Read<PEB_LDR_DATA>(m_memory.Read<size_t>(GET_FIELD_PTR(pPeb, Ldr)));
                PLDR_DATA_TABLE_ENTRY NtdllEntry = CONTAINING_RECORD(Ldr.InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

                if (VirtualQueryEx(m_memory.m_hProcess, NtdllEntry, &mbi, sizeof(mbi)))
                {
                    m_LdrHeapBase = (size_t)mbi.AllocationBase;
                    return true;
                }
            }

            return false;
        }

    }
}
