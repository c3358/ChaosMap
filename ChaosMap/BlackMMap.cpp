#include "BlackMMap.h"

namespace ds_mmap
{
    CBlackMMap::CBlackMMap(DWORD pid)
        : m_pTopImage(nullptr)
        , m_tlsIndex(0)
        , m_pAContext(nullptr)
    {
        m_TargetProcess.Attach(pid);
    }

    CBlackMMap::~CBlackMMap(void)
    {
        UnmapAllModules();
    }

    FARPROC CBlackMMap::GetProcAddressEx( HMODULE mod, const char* procName )
    {
        return m_TargetProcess.Modules.GetProcAddressEx(mod, procName);
    }

    bool CBlackMMap::CallFunction( void* pFn, std::initializer_list<GenVar> args, size_t& result, eCalligConvention cc /*= CC_cdecl*/, HANDLE hContextThread /*= INVALID_HANDLE_VALUE*/ )
    {
        AsmJit::Assembler a;
        AsmJitHelper ah(a);

        if(cc < CC_cdecl || cc > CC_fastcall)
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return false;
        }

        ah.GenPrologue();
        ah.GenCall(pFn, args, cc);

        if(hContextThread == INVALID_HANDLE_VALUE || hContextThread != NULL)
        {
            if(m_TargetProcess.Core.CreateRPCEnvironment(true) != ERROR_SUCCESS)
                return false;

            ah.SaveRetValAndSignalEvent();
            ah.GenEpilogue();

            if(hContextThread == INVALID_HANDLE_VALUE)
                m_TargetProcess.Core.ExecInWorkerThread(a.make(), a.getCodeSize(), result);
            else
                m_TargetProcess.Core.ExecInAnyThread(a.make(), a.getCodeSize(), result, hContextThread);
        }
        else
        {
            size_t tmp = 0;

            ah.ExitThreadWithStatus();
            ah.GenEpilogue();

            m_TargetProcess.Core.RemoteCall(a.make(), a.getCodeSize(), result, &tmp);
        }

        return true;
    }

    HMODULE CBlackMMap::MapDll( const std::string& path, eLoadFlags flags /*= NoFlags*/)
    {
        wchar_t tmp[1024] = {0};

        MultiByteToWideChar(CP_ACP, 0, path.c_str(), (int)path.length(), tmp, ARRAYSIZE(tmp));

        return MapDll(tmp, flags);
    }

    HMODULE CBlackMMap::MapDll( const std::wstring& path, eLoadFlags flags /*= NoFlags*/ )
    {
        std::tr2::sys::wpath tmpPath(path);
        ImageContext *pOldImage = m_pTopImage;

        m_pTopImage           = new ImageContext();
        m_pTopImage->FilePath = path;
        m_pTopImage->FileName = m_pTopImage->FilePath.filename();
        m_pTopImage->flags    = flags;

        if(!m_pTopImage->Image.Project(path) || !m_pTopImage->ImagePE.Parse(m_pTopImage->Image, m_pTopImage->Image.isPlainData()))
        {
            delete m_pTopImage;
            m_pTopImage = pOldImage;
            return 0;
        }
        
        if(m_TargetProcess.Core.CreateRPCEnvironment() != ERROR_SUCCESS)
        {
            delete m_pTopImage;
            m_pTopImage = pOldImage;
            return 0;
        }

        if(HMODULE hMod = m_TargetProcess.Modules.GetModuleAddress(m_pTopImage->FileName.c_str()))
        {
            delete m_pTopImage;
            m_pTopImage = pOldImage;
            return hMod;
        }

        m_pTopImage->pTargetBase = (void*)m_pTopImage->ImagePE.ImageBase();

        DWORD dwResult = m_TargetProcess.Core.Allocate(m_pTopImage->ImagePE.ImageSize(), m_pTopImage->pTargetBase);
        if(dwResult != ERROR_SUCCESS && dwResult != ERROR_IMAGE_NOT_AT_BASE)
        {
            delete m_pTopImage;
            m_pTopImage = pOldImage;
            return 0;
        }

        if(!(flags & NoExceptions))
        {
            ds_process::CProcess::pImageBase = m_pTopImage->pTargetBase;
            ds_process::CProcess::imageSize  = m_pTopImage->ImagePE.ImageSize();
        }

        if(!(flags & NoSxS))
            m_TargetProcess.Modules.PushLocalActx(m_pTopImage->Image.actx());

        if(!(flags & NoSxS))
        {
            if(!CreateActx(2))
                CreateActx(1);
        }

        if(!CopyImage() || !RelocateImage())
        {
            delete m_pTopImage;
            m_pTopImage = pOldImage;
            return 0;
        }

        /*if(m_pTopImage->ImagePE.IsPureManaged())
            return MapPureManaged();*/
        
       m_TargetProcess.Modules.AddManualModule(m_pTopImage->FileName, (HMODULE)m_pTopImage->pTargetBase);

        if(flags & CreateLdrRef)
            m_TargetProcess.Modules.NtLoader().CreateNTReference(
                (HMODULE)m_pTopImage->pTargetBase, m_pTopImage->ImagePE.ImageSize(), m_pTopImage->FileName, m_pTopImage->FilePath);

        if(!ResolveImport() || (!(flags & NoDelayLoad) && !ResolveDelayImport()))
        {
            delete m_pTopImage;
            m_pTopImage = pOldImage;
            return 0;
        }

        ProtectImageMemory();

        if(/*m_TargetProcess.DisabeDEP() != ERROR_SUCCESS &&*/
            !(flags & NoExceptions) && !EnableExceptions())
        {
            delete m_pTopImage;
            m_pTopImage = pOldImage;
            return 0;
        }

        if(m_pTopImage->flags & UnlinkVAD)
            m_TargetProcess.UnlinkVad(m_pTopImage->pTargetBase, m_pTopImage->ImagePE.ImageSize());

        if(!(flags & NoTLS))
        {
            m_pTopImage->ImagePE.GetTLSCallbacks(m_pTopImage->pTargetBase, m_pTopImage->tlsCallbacks);

            if(!InitStaticTLS() || !RunTLSInitializers(DLL_PROCESS_ATTACH))
            {
                delete m_pTopImage;
                m_pTopImage = pOldImage;
                return 0;
            }
        }

        InitializeCookie();
        
        if(flags & RebaseProcess && m_pTopImage->ImagePE.IsExe() && pOldImage == nullptr)
            m_TargetProcess.Core.Write((size_t)m_TargetProcess.Core.GetPebBase() + 2 * WordSize, (size_t)m_pTopImage->pTargetBase);

        if((m_pTopImage->EntryPoint = (pDllMain)m_pTopImage->ImagePE.EntryPoint(m_pTopImage->pTargetBase)) != nullptr)      
            CallEntryPoint(DLL_PROCESS_ATTACH);       

        m_pTopImage->Image.Release();

        if(!(flags & NoSxS))
            m_TargetProcess.Modules.PopLocalActx();

        m_Images.emplace_back(m_pTopImage);
        m_pTopImage = pOldImage;


        return (HMODULE)m_Images.back()->pTargetBase;
    }

    HMODULE CBlackMMap::MapPureManaged()
    {
        CImageNET netImg;

        if(!netImg.Init(m_pTopImage->FilePath))
        {
            SetLastError(0x1337);
            return 0;
        }

        netImg.Parse();

        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return 0;
        //return (HMODULE)m_pTopImage->pTargetBase;
    }

    bool CBlackMMap::UnmapAllModules()
    {
        for (auto iter = m_Images.rbegin(); iter != m_Images.rend(); iter++)
        {
            m_pTopImage = iter->get();

            if(!(m_pTopImage->flags & NoTLS))
                RunTLSInitializers(DLL_PROCESS_DETACH);

            CallEntryPoint(DLL_PROCESS_DETACH);

            FreeActx();

            if(!(m_pTopImage->flags & NoExceptions))
                DisableExceptions();

            m_TargetProcess.Core.Free(m_pTopImage->pTargetBase);

            m_TargetProcess.Modules.RemoveManualModule(m_pTopImage->FilePath.filename());
        }        

        m_TargetProcess.Core.TerminateWorkerThread();

        m_Images.clear();
        m_pTopImage = nullptr;

        return true;
    }

    bool CBlackMMap::CBlackMMap()
    {
        size_t dwHeaderSize = m_pTopImage->ImagePE.HeadersSize();

        if(m_TargetProcess.Core.Write(m_pTopImage->pTargetBase, dwHeaderSize, m_pTopImage->Image.base()) != ERROR_SUCCESS)
            return false;

        if(m_TargetProcess.Core.Protect(m_pTopImage->pTargetBase, dwHeaderSize, PAGE_READONLY) != ERROR_SUCCESS)
            return false;

        auto sections = m_pTopImage->ImagePE.Sections();

        for( auto& section : sections)
        {
            if(!(section.Characteristics & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)))
                continue;

            uint8_t* pSource = (uint8_t*)m_pTopImage->ImagePE.ResolveRvaToVA(section.VirtualAddress);

            if(m_TargetProcess.Core.Write((uint8_t*)m_pTopImage->pTargetBase + section.VirtualAddress, section.Misc.VirtualSize, pSource) != ERROR_SUCCESS)
                return false;
        }

        return true;
    }

    bool CBlackMMap::CBlackMMap()
    {
        size_t Delta = 0;
        ds_pe::IMAGE_BASE_RELOCATION2* fixrec = (ds_pe::IMAGE_BASE_RELOCATION2*)m_pTopImage->ImagePE.DirectoryAddress(IMAGE_DIRECTORY_ENTRY_BASERELOC);

        Delta = (size_t)m_pTopImage->pTargetBase - (size_t)m_pTopImage->ImagePE.ImageBase();

        if(Delta == 0)
        {
            SetLastError(ERROR_SUCCESS);
            return true;
        }

        if (fixrec == nullptr) 
        {
            SetLastError(err::mapping::CantRelocate);
            return false;
        }

        while (fixrec->BlockSize)                        
        {
            DWORD count = (fixrec->BlockSize - 8) >> 1;             

            for (DWORD i = 0; i < count; ++i)
            {
                WORD fixtype    = (fixrec->Item[i].Type);           
                WORD fixoffset  = (fixrec->Item[i].Offset) % 4096;  

                if (fixtype == IMAGE_REL_BASED_ABSOLUTE) 
                    continue;

                if (fixtype == IMAGE_REL_BASED_HIGHLOW || fixtype == IMAGE_REL_BASED_DIR64) 
                {
                    size_t targetAddr = (size_t)m_pTopImage->pTargetBase + fixoffset + fixrec->PageRVA;
                    size_t sourceAddr = *(size_t*)((size_t)m_pTopImage->Image.base() + fixoffset + fixrec->PageRVA) + Delta;

                    if(m_TargetProcess.Core.Write(targetAddr, sourceAddr) != ERROR_SUCCESS)
                        return false;
                }
                else
                {
                    SetLastError(err::mapping::AbnormalRelocation);
                    return false;
                }
            }

            fixrec = (ds_pe::IMAGE_BASE_RELOCATION2*)((size_t)fixrec + fixrec->BlockSize);
        } 

        return true;
    }

    bool CBlackMMap::ResolveImport()
    {
        IMAGE_IMPORT_DESCRIPTOR *pImportTbl = (IMAGE_IMPORT_DESCRIPTOR*)m_pTopImage->ImagePE.DirectoryAddress(IMAGE_DIRECTORY_ENTRY_IMPORT);
        void* base                          = m_pTopImage->Image.base();

        if(!pImportTbl)
            return true;
        
        for (; pImportTbl->Name; ++pImportTbl)
        {
            IMAGE_THUNK_DATA* pRVA  = nullptr;
            DWORD IAT_Index         = 0;
            char *pDllName          = MAKE_PTR(char*, pImportTbl->Name, base);
            std::string strDll      = pDllName;
            std::wstring strBaseDll = L"";
            HMODULE hMod            = m_TargetProcess.Modules.GetModuleAddress(pDllName, false, m_pTopImage->FileName.c_str());

            strBaseDll.assign(strDll.begin(), strDll.end());
            m_TargetProcess.Modules.ResolvePath(strBaseDll, ds_process::Default, m_pTopImage->FileName);

            if(!hMod)
            {      
                m_TargetProcess.Modules.ResolvePath(strDll, ds_process::EnsureFullPath);

            #ifdef _M_AMD64
                eLoadFlags newFlags = (eLoadFlags)(m_pTopImage->flags | NoDelayLoad | NoSxS);
            #else
                eLoadFlags newFlags = (eLoadFlags)(m_pTopImage->flags | NoDelayLoad | NoSxS | PartialExcept);
            #endif

                if(m_pTopImage->flags & ManualImports)
                    hMod = MapDll(strDll, newFlags);
                else
                    hMod = m_TargetProcess.Modules.SimpleInject(strDll.c_str(), m_pAContext);

                if(!hMod)
                {
                    printf("Missing import %s\n", strDll.c_str());

                    if(GetLastError() == ERROR_SUCCESS)
                        SetLastError(err::mapping::CantResolveImport);

                    return false;
                }            
            }

            if (pImportTbl->OriginalFirstThunk)
                pRVA = MAKE_PTR(IMAGE_THUNK_DATA*, pImportTbl->OriginalFirstThunk, base);
            else
                pRVA = MAKE_PTR(IMAGE_THUNK_DATA*, pImportTbl->FirstThunk, base);

            while (pRVA->u1.AddressOfData)
            {
                IMAGE_IMPORT_BY_NAME* pAddressTable = MAKE_PTR(IMAGE_IMPORT_BY_NAME*, pRVA->u1.AddressOfData, base);
                void* pFuncPtr                      = 0;
                size_t dwIATAddress                 = 0;                

                if ((size_t)pRVA->u1.AddressOfData < (1LL << (WordSize * 8 - 1) ) && pAddressTable->Name[0])
                {
                    pFuncPtr = m_TargetProcess.Modules.GetProcAddressEx(hMod, pAddressTable->Name, strBaseDll.c_str());
                }
                else 
                {
                    pFuncPtr = m_TargetProcess.Modules.GetProcAddressEx(hMod, (char*)((USHORT)pRVA->u1.AddressOfData & 0xFFFF), strBaseDll.c_str());
                }

                if(pFuncPtr == nullptr)
                {
                    SetLastError(err::mapping::NoImportFunction);
                    return false;
                }

                if (pImportTbl->FirstThunk)
                {
                    dwIATAddress = pImportTbl->FirstThunk + (size_t)m_pTopImage->pTargetBase + IAT_Index;
                }
                else
                {
                    dwIATAddress = pRVA->u1.AddressOfData - (size_t)base + (size_t)m_pTopImage->pTargetBase;
                }

                m_TargetProcess.Core.Write(dwIATAddress, pFuncPtr);

                pRVA++;
                IAT_Index += WordSize;
            }
        }

        return true;
    }

    bool CBlackMMap::ResolveDelayImport()
    {
        IMAGE_DELAYLOAD_DESCRIPTOR *pDelayLoad = (IMAGE_DELAYLOAD_DESCRIPTOR*)m_pTopImage->ImagePE.DirectoryAddress(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
        void* base                             = m_pTopImage->Image.base();

        if(!pDelayLoad)
            return true;

        for (; pDelayLoad->DllNameRVA; ++pDelayLoad)
        {
            IMAGE_THUNK_DATA* pRVA  = nullptr;
            DWORD IAT_Index         = 0;
            char *pDllName          = MAKE_PTR(char*, pDelayLoad->DllNameRVA, base);
            std::string strDll      = pDllName;
            std::wstring strBaseDll = L"";
            HMODULE hMod            = m_TargetProcess.Modules.GetModuleAddress(pDllName, false, m_pTopImage->FileName.c_str());

            strBaseDll.assign(strDll.begin(), strDll.end());
            m_TargetProcess.Modules.ResolvePath(strBaseDll, ds_process::Default, m_pTopImage->FileName);

            if(!hMod)
            {
                m_TargetProcess.Modules.ResolvePath(strDll, ds_process::EnsureFullPath);

            #ifdef _M_AMD64
                eLoadFlags newFlags = (eLoadFlags)(m_pTopImage->flags | NoDelayLoad | NoSxS);
            #else
                eLoadFlags newFlags = (eLoadFlags)(m_pTopImage->flags | NoDelayLoad | NoSxS | PartialExcept);
            #endif

                if(m_pTopImage->flags & ManualImports)
                    hMod = MapDll(strDll, newFlags);
                else
                    hMod = m_TargetProcess.Modules.SimpleInject(strDll.c_str(), m_pAContext);

                if(!hMod)
                    continue;      
            }
            
            pRVA = MAKE_PTR(IMAGE_THUNK_DATA*, pDelayLoad->ImportNameTableRVA, base);

            while (pRVA->u1.AddressOfData)
            {
                IMAGE_IMPORT_BY_NAME* pAddressTable = MAKE_PTR(IMAGE_IMPORT_BY_NAME*, pRVA->u1.AddressOfData, base);
                void* pFuncPtr                      = 0;
                size_t dwIATAddress                 = 0; 

                if ((size_t)pAddressTable < (1LL << (WordSize * 8 - 1) ) && pAddressTable->Name[0])
                {
                    pFuncPtr = m_TargetProcess.Modules.GetProcAddressEx(hMod, pAddressTable->Name, strBaseDll.c_str());
                }
                else 
                {
                    pFuncPtr = m_TargetProcess.Modules.GetProcAddressEx(hMod, (char*)((USHORT)pAddressTable & 0xFFFF), strBaseDll.c_str());
                }

                if(pFuncPtr == nullptr)
                {
                    SetLastError(err::mapping::NoImportFunction);
                    return false;
                }

                dwIATAddress = pDelayLoad->ImportAddressTableRVA + (size_t)m_pTopImage->pTargetBase + IAT_Index;

                m_TargetProcess.Core.Write(dwIATAddress, pFuncPtr);

                pRVA++;
                IAT_Index += WordSize;
            }
        }


        return true;
    }

    bool CBlackMMap::EnableExceptions()
    {
    #ifdef _M_AMD64
        size_t size = m_pTopImage->ImagePE.DirectorySize(IMAGE_DIRECTORY_ENTRY_EXCEPTION);
        IMAGE_RUNTIME_FUNCTION_ENTRY *pExpTable = (IMAGE_RUNTIME_FUNCTION_ENTRY*)m_pTopImage->ImagePE.DirectoryAddress(IMAGE_DIRECTORY_ENTRY_EXCEPTION);

        if(pExpTable)
        {
            AsmJit::Assembler a;
            AsmJitHelper ah(a);
            size_t result = 0;

            m_pTopImage->pExpTableAddr = REBASE(pExpTable, m_pTopImage->Image.base(), m_pTopImage->pTargetBase);

            ah.GenPrologue();

            ah.GenCall(&RtlAddFunctionTable, { m_pTopImage->pExpTableAddr, size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (size_t)m_pTopImage->pTargetBase });

            ah.SaveRetValAndSignalEvent();
            ah.GenEpilogue();

            if(m_TargetProcess.Core.ExecInWorkerThread(a.make(), a.getCodeSize(), result) != ERROR_SUCCESS)
                return false;

            if(m_pTopImage->flags & CreateLdrRef)
                return true;
            else
                return (m_TargetProcess.CreateVEH((size_t)m_pTopImage->pTargetBase, m_pTopImage->ImagePE.ImageSize()) == ERROR_SUCCESS);
        }
        else
            return false;
    #else
        m_TargetProcess.Modules.NtLoader().InsertInvertedFunctionTable(m_pTopImage->pTargetBase, m_pTopImage->ImagePE.ImageSize());

        if(m_pTopImage->flags & PartialExcept)
            return true;
        else
            return (m_TargetProcess.CreateVEH((size_t)m_pTopImage->pTargetBase, m_pTopImage->ImagePE.ImageSize()) == ERROR_SUCCESS);
    #endif
    }

    bool CBlackMMap::DisableExceptions()
    {
    #ifdef _M_AMD64
        if(m_pTopImage->pExpTableAddr)
        {
            AsmJit::Assembler a;
            AsmJitHelper ah(a);
            size_t result = 0;

            ah.GenPrologue();

            ah.GenCall(&RtlDeleteFunctionTable, { m_pTopImage->pExpTableAddr });

            ah.SaveRetValAndSignalEvent();
            ah.GenEpilogue();
           
            if(m_TargetProcess.Core.ExecInWorkerThread(a.make(), a.getCodeSize(), result) != ERROR_SUCCESS)
                return false;

            if(m_pTopImage->flags & CreateLdrRef)
                return true;
            else
                return (m_TargetProcess.RemoveVEH() == ERROR_SUCCESS);
        }
        else
            return false;
    #else
        if(m_pTopImage->flags & (PartialExcept | NoExceptions))
            return true;
        else
            return (m_TargetProcess.RemoveVEH() == ERROR_SUCCESS);

    #endif
    }

    bool CBlackMMap::InitStaticTLS()
    {
        IMAGE_TLS_DIRECTORY *pTls = (IMAGE_TLS_DIRECTORY*)m_pTopImage->ImagePE.DirectoryAddress(IMAGE_DIRECTORY_ENTRY_TLS);

        if(pTls && pTls->AddressOfIndex)
        {
            m_TargetProcess.Modules.NtLoader().AddStaticTLSEntry(m_pTopImage->pTargetBase);

            /*AsmJit::Assembler a;
            AsmJitHelper ah(a);
            size_t result = 0;

            ah.GenPrologue();

            // HeapAlloc(GetProcessHeap, HEAP_ZERO_MEMORY, 4);
            ah.GenCall(&GetProcessHeap, { });
            a.mov(AsmJit::nsi, AsmJit::nax);

            ah.GenCall(&HeapAlloc, { AsmJit::nsi, 0xC0000 | HEAP_ZERO_MEMORY, 6 * WordSize });
            a.mov(AsmJit::ndi, AsmJit::nax);

            ah.GenCall(&HeapAlloc, { AsmJit::nsi, 0xC0000 | HEAP_ZERO_MEMORY, pTls->EndAddressOfRawData - pTls->StartAddressOfRawData + pTls->SizeOfZeroFill + 8 });
            a.mov(AsmJit::nbx, AsmJit::nax);

        #ifdef _M_IX86       
            // mov eax, fs:[0x18]
            a._emitWord(0xA164);
            a._emitDWord(0x18);          
        #else
            // mov rax, gs:[0x30]
            a._emitByte(0x65);          
            a._emitDWord(0x25048B48);
            a._emitDWord(0x30);
        #endif
            void *pCopyFunc = GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "memcpy");

            a.add(AsmJit::nax, 0xB*WordSize);
            a.mov(AsmJit::sysint_ptr(AsmJit::nax), AsmJit::ndi);
            ah.GenCall(pCopyFunc, { AsmJit::nbx, 
                                    REBASE(pTls->StartAddressOfRawData,  m_pTopImage->ImagePE.ImageBase(), m_pTopImage->pTargetBase), 
                                    pTls->EndAddressOfRawData - pTls->StartAddressOfRawData });

            a.mov(AsmJit::sysint_ptr(AsmJit::ndi, WordSize*m_tlsIndex), AsmJit::nbx);

            ah.SaveRetValAndSignalEvent();
            ah.GenEpilogue();

            m_TargetProcess.Core.ExecInWorkerThread(a.make(), a.getCodeSize(), result);

            m_TargetProcess.Core.Write<int>(REBASE(pTls->AddressOfIndex, m_pTopImage->ImagePE.ImageBase(), m_pTopImage->pTargetBase), m_tlsIndex);

            m_tlsIndex++;*/
        }

        return true;
    }

    bool CBlackMMap::RunTLSInitializers( DWORD dwReason )
    {
        AsmJit::Assembler a;
        AsmJitHelper ah(a);
        size_t result = 0;

        if(m_pTopImage->tlsCallbacks.empty())
            return true;

        ah.GenPrologue();

        if(m_pAContext)
        {
            a.mov(AsmJit::nax, (size_t)m_pAContext);
            a.mov(AsmJit::nax, AsmJit::dword_ptr(AsmJit::nax));
            ah.GenCall(&ActivateActCtx, {AsmJit::nax, (size_t)m_pAContext + sizeof(HANDLE)});
        }

        for (auto& pCallback : m_pTopImage->tlsCallbacks)
            ah.GenCall(pCallback, {(size_t)m_pTopImage->pTargetBase, dwReason, NULL});

        if(m_pAContext)
        {
            a.mov(AsmJit::nax, (size_t)m_pAContext + sizeof(HANDLE));
            a.mov(AsmJit::nax, AsmJit::dword_ptr(AsmJit::nax));
            ah.GenCall(&DeactivateActCtx, {0, AsmJit::nax});
        }

        ah.SaveRetValAndSignalEvent();
        ah.GenEpilogue();

        m_TargetProcess.Core.ExecInWorkerThread(a.make(), a.getCodeSize(), result);
                
        return true;
    }

    bool CBlackMMap::InitializeCookie()
    {
        IMAGE_LOAD_CONFIG_DIRECTORY *pLC = (IMAGE_LOAD_CONFIG_DIRECTORY*)m_pTopImage->ImagePE.DirectoryAddress(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);

        if(pLC && pLC->SecurityCookie)
        {
            FILETIME systime = {0};
            LARGE_INTEGER PerformanceCount = {0};
            int cookie = 0;

            GetSystemTimeAsFileTime(&systime);
            QueryPerformanceCounter(&PerformanceCount);

            cookie  = systime.dwHighDateTime ^ systime.dwLowDateTime ^ GetCurrentThreadId();
            cookie ^= GetCurrentProcessId();
            cookie ^= PerformanceCount.LowPart;
            cookie ^= PerformanceCount.HighPart;
            cookie ^= (unsigned int)&cookie;

            if ( cookie == 0xBB40E64E )
                cookie = 0xBB40E64F;
            else if ( !(cookie & 0xFFFF0000) )       
                cookie |= (cookie | 0x4711) << 16;

            m_TargetProcess.Core.Write<int>(REBASE(pLC->SecurityCookie, m_pTopImage->ImagePE.ImageBase(), m_pTopImage->pTargetBase), cookie); 
        }

        return true;
    }

    bool CBlackMMap::CallEntryPoint( DWORD dwReason )
    {
        AsmJit::Assembler a;
        AsmJitHelper ah(a);
        size_t result = 0;

        ah.GenPrologue();

        if(m_pAContext)
        {
            a.mov(AsmJit::nax, (size_t)m_pAContext);
            a.mov(AsmJit::nax, AsmJit::dword_ptr(AsmJit::nax));
            ah.GenCall(&ActivateActCtx, { AsmJit::nax, (size_t)m_pAContext + sizeof(HANDLE) });
        }

        ah.GenCall(m_pTopImage->EntryPoint, { (size_t)m_pTopImage->pTargetBase, dwReason, NULL });

        if(m_pAContext)
        {
            a.mov(AsmJit::nax, (size_t)m_pAContext + sizeof(HANDLE));
            a.mov(AsmJit::nax, AsmJit::dword_ptr(AsmJit::nax));
            ah.GenCall(&DeactivateActCtx, { 0, AsmJit::nax });
        }

        ah.SaveRetValAndSignalEvent();
        ah.GenEpilogue();

        m_TargetProcess.Core.ExecInWorkerThread(a.make(), a.getCodeSize(), result);

        return true;
    }

    bool CBlackMMap::CreateActx( int id /*= 2*/ )
    {
        AsmJit::Assembler a;
        AsmJitHelper ah(a);

        size_t   result = 0;
        ACTCTX   act    = {0};

        m_TargetProcess.Core.Allocate(512, m_pAContext);

        act.cbSize          = sizeof(act);
        act.dwFlags         = ACTCTX_FLAG_RESOURCE_NAME_VALID;
        act.lpSource        = (LPCWSTR)((SIZE_T)m_pAContext + sizeof(HANDLE) + sizeof(act));
        act.lpResourceName  = MAKEINTRESOURCE(id);

        ah.GenPrologue();

        ah.GenCall(&CreateActCtx, {(size_t)m_pAContext + sizeof(HANDLE)});

        // pTopImage->pAContext = CreateActCtx(&act)
        a.mov(AsmJit::ndx, (size_t)m_pAContext);
        a.mov(AsmJit::sysint_ptr(AsmJit::ndx), AsmJit::nax);

        ah.SaveRetValAndSignalEvent();
        ah.GenEpilogue();

        m_TargetProcess.Core.Write((BYTE*)m_pAContext + sizeof(HANDLE), sizeof(act), &act);
        m_TargetProcess.Core.Write((BYTE*)m_pAContext + sizeof(HANDLE) + sizeof(act), 
            (m_pTopImage->FilePath.string().length() + 1)*sizeof(TCHAR) , (void*)m_pTopImage->FilePath.string().c_str());

        if(m_TargetProcess.Core.ExecInWorkerThread(a.make(), a.getCodeSize(), result) != ERROR_SUCCESS || (HANDLE)result == INVALID_HANDLE_VALUE)
        {
            if(m_TargetProcess.Core.Free(m_pAContext) == ERROR_SUCCESS)
                m_pAContext = nullptr;

            SetLastError(err::mapping::CantCreateActx);
            return false;
        }

        return true;
    }

    bool CBlackMMap::FreeActx()
    {
        if(m_pAContext)
        {
            m_TargetProcess.Core.Free(m_pAContext);
            m_pAContext = nullptr;
        }

        return true;
    }

    DWORD CBlackMMap::GetSectionProt( DWORD characteristics )
    {
        DWORD dwResult = PAGE_NOACCESS;

        if(characteristics & IMAGE_SCN_MEM_EXECUTE) 
        {
            if(characteristics & IMAGE_SCN_MEM_WRITE)
                dwResult = PAGE_EXECUTE_READWRITE;
            else if(characteristics & IMAGE_SCN_MEM_READ)
                dwResult = PAGE_EXECUTE_READ;
            else
                dwResult = PAGE_EXECUTE;
        } 
        else
        {
            if(characteristics & IMAGE_SCN_MEM_WRITE)
                dwResult = PAGE_READWRITE;
            else if(characteristics & IMAGE_SCN_MEM_READ)
                dwResult = PAGE_READONLY;
            else
                dwResult = PAGE_NOACCESS;
        }

        return dwResult;
    }
}