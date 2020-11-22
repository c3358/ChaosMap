#include "MemModules.h"

namespace ds_mmap
{
    namespace ds_process
    {
        CMemModules::mapApiSchema CMemModules::m_ApiSchemaMap;

        CMemModules::CMemModules(CMemCore& mem)
            : m_memory(mem)
            , m_native(mem)
        {
            InitApiSchema();
        }

        CMemModules::~CMemModules(void)
        {
        }

        HMODULE CMemModules::SimpleInject( const std::string& dllName, void *pActx /*= nullptr */ )
        {
            size_t  result              = 0; 
            LPVOID  pDllName            = NULL; 

            std::string dllFinal(dllName);
 
            if(!m_memory.m_hProcess)
                return NULL;

           ResolvePath(dllFinal, EnsureFullPath);
           std::tr2::sys::path dllPath(dllFinal);

           if(HMODULE addr = GetModuleAddress(dllPath.filename().c_str()))
               return addr;

            m_memory.Allocate(MAX_PATH, pDllName);

            if(m_memory.Write(pDllName, dllFinal.length() + 1, (void*)dllFinal.c_str()) != ERROR_SUCCESS)
            {
                m_memory.Free(pDllName);
                return NULL;
            }

            if(pActx == nullptr)
            {
                m_memory.RemoteCallDirect(&LoadLibraryA, pDllName, result);

                #ifdef _M_AMD64
                    result = (size_t)GetModuleAddress(dllPath.filename().c_str());
                #endif
            }
            else
            {
                AsmJit::Assembler a;
                AsmJitHelper ah(a);

                ah.GenPrologue();

                a.mov(AsmJit::nax, (size_t)pActx);
                a.mov(AsmJit::nax, AsmJit::dword_ptr(AsmJit::nax));
                ah.GenCall(&ActivateActCtx, {AsmJit::nax, (size_t)pActx + sizeof(HANDLE)});

                ah.GenCall(&LoadLibraryA, {(size_t)pDllName});
                a.mov(AsmJit::ndi, AsmJit::nax);

                a.mov(AsmJit::nax, (size_t)pActx + sizeof(HANDLE));
                a.mov(AsmJit::nax, AsmJit::dword_ptr(AsmJit::nax));
                ah.GenCall(&DeactivateActCtx, {0, AsmJit::nax});
                a.mov(AsmJit::nax, AsmJit::ndi);

                ah.SaveRetValAndSignalEvent();
                ah.GenEpilogue();

                m_memory.ExecInWorkerThread(a.make(), a.getCodeSize(), result);
            }
    
            m_memory.Free(pDllName);

            return (HMODULE)result;
        }

        DWORD CMemModules::SimpleUnload( const std::string& dllName )
        {
            HMODULE hDll = NULL;

            if(!m_memory.m_hProcess)
                return ERROR_INVALID_HANDLE;

            if((hDll = GetModuleAddress(dllName.c_str(), true)) != 0)
            {
                size_t result = 0;
                m_memory.RemoteCallDirect(&FreeLibrary, (void*)hDll, result);
            }

            return ERROR_SUCCESS;
        }

        DWORD CMemModules::ResolvePath(std::string& path, eResolveFlag flags, const std::wstring& baseName /*= ""*/)
        {
            std::wstring wpathStr;
            std::wstring wbaseStr;

            wpathStr.assign(path.begin(), path.end());
            wbaseStr.assign(baseName.begin(), baseName.end());

            DWORD res = ResolvePath(wpathStr, flags);

            path.assign(wpathStr.begin(), wpathStr.end());

            return res;
        }

        DWORD CMemModules::ResolvePath(std::wstring& path, eResolveFlag flags, const std::wstring& baseName /*= L""*/)
        {
            wchar_t tmpPath[4096] = {0};

            std::transform(path.begin(), path.end(), path.begin(), ::tolower);

            std::tr2::sys::wpath wpath(path);
            std::tr2::sys::wpath wSearchPath;

            if(wpath.is_complete())
                return ERROR_SUCCESS;

            wpath = wpath.filename();

            if(wpath.string().find(L"ext-ms-") == 0)
                wpath = wpath.string().replace(0, 3, L"api");
      
            auto iter = m_ApiSchemaMap.find(wpath.filename());

            if(iter != m_ApiSchemaMap.end())
            {
                if(iter->second.front() != baseName)
                    path.assign(iter->second.front().begin(), iter->second.front().end());
                else
                    path.assign(iter->second.back().begin(), iter->second.back().end());

                if(ProbeSxSRedirect(path) == ERROR_SUCCESS)
                    return ERROR_SUCCESS;
                else if(flags & EnsureFullPath)
                    path = L"C:\\windows\\system32\\" + path;

                return ERROR_SUCCESS;
            }

            if(flags & ApiSchemaOnly)
            {
                SetLastError(ERROR_NOT_FOUND);
                return ERROR_NOT_FOUND;
            }

            if(ProbeSxSRedirect(path) == ERROR_SUCCESS)
                return ERROR_SUCCESS;

            HKEY hKey = NULL;
            LRESULT res = 0;
            res = RegOpenKey(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs", &hKey);

            if(res == 0)
            {
                for(int i = 0; i < 0x1000 && res == ERROR_SUCCESS; i++)
                {
                    wchar_t value_name[255] = {0};
                    wchar_t value_data[255] = {0};

                    DWORD dwSize = 255;
                    DWORD dwType = 0;

                    res = SHEnumValue(hKey, i, value_name, &dwSize, &dwType, value_data, &dwSize);

                    if(_wcsicmp(value_data, wpath.filename().c_str()) == 0)
                    {
                        wchar_t sys_path[255] = {0};
                        dwSize = 255;

                        res = SHGetValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs", 
                            L"DllDirectory", &dwType, sys_path, &dwSize);

                        if(res == ERROR_SUCCESS)
                        {
                            path = std::wstring(sys_path) + L"\\" + value_data;

                            RegCloseKey(hKey);
                            return ERROR_SUCCESS;
                        }
                    }
                }       

                RegCloseKey(hKey);
            }

            std::tr2::sys::wpath wBasePath(GetProcessDirectory());
            wBasePath = wBasePath.parent_path();

            wSearchPath = std::tr2::sys::complete(wpath, wBasePath);
    
            if(std::tr2::sys::exists(wSearchPath))
            {
                path = wSearchPath.string();
                return ERROR_SUCCESS;
            }

            GetSystemDirectory(tmpPath, ARRAYSIZE(tmpPath));

            wBasePath   = tmpPath;
            wSearchPath = std::tr2::sys::complete(wpath, wBasePath);

            if(std::tr2::sys::exists(wSearchPath))
            {
                path = wSearchPath.string();
                return ERROR_SUCCESS;
            }


            GetWindowsDirectory(tmpPath, ARRAYSIZE(tmpPath));

            wBasePath   = tmpPath;
            wSearchPath = std::tr2::sys::complete(wpath, wBasePath);

            if(std::tr2::sys::exists(wSearchPath))
            {
                path = wSearchPath.string();
                return ERROR_SUCCESS;
            }

            GetCurrentDirectory(ARRAYSIZE(tmpPath), tmpPath);

            wBasePath   = tmpPath;
            wSearchPath = std::tr2::sys::complete(wpath, wBasePath);

            if(std::tr2::sys::exists(wSearchPath))
            {
                path = wSearchPath.string();
                return ERROR_SUCCESS;
            }

            GetEnvironmentVariable(L"PATH", tmpPath, ARRAYSIZE(tmpPath));
            wchar_t *pContext; 

            for(wchar_t *pDir = wcstok_s(tmpPath, L";", &pContext); pDir ; pDir = wcstok_s(pContext, L";", &pContext))
            {
                wBasePath   = pDir;
                wSearchPath = std::tr2::sys::complete(wpath, wBasePath);

                if(std::tr2::sys::exists(wSearchPath))
                {
                    path = wSearchPath.string();
                    return ERROR_SUCCESS;
                }
            }

            SetLastError(ERROR_NOT_FOUND);
            return ERROR_NOT_FOUND;
        }

        DWORD CMemModules::ProbeSxSRedirect( std::wstring& path )
        {
            UNICODE_STRING OriginalName;
            UNICODE_STRING Extension;
            UNICODE_STRING DllName1;
            UNICODE_STRING DllName2;
            PUNICODE_STRING pPath = nullptr;
            ULONG_PTR cookie = 0;
            HANDLE hCtx = m_ActxStack.empty() ? INVALID_HANDLE_VALUE : m_ActxStack.top();
            wchar_t wBuf[255];

            if(path.rfind(L".dll") != std::wstring::npos)
                path.erase(path.rfind(L".dll"));

            RtlInitUnicodeString(&Extension, L".dll");
            RtlInitUnicodeString(&OriginalName, path.c_str());
            RtlInitUnicodeString(&DllName2, L"");

            DllName1.Buffer         = wBuf;
            DllName1.Length         = NULL;
            DllName1.MaximumLength  = ARRAYSIZE(wBuf);

            if(hCtx && hCtx != INVALID_HANDLE_VALUE)
                ActivateActCtx(hCtx, &cookie);

            NTSTATUS status = RtlDosApplyFileIsolationRedirection_Ustr(1, &OriginalName, &Extension, &DllName1, &DllName2, &pPath, 
                NULL, NULL, NULL);

            if(cookie != 0 && hCtx && hCtx != INVALID_HANDLE_VALUE)
                DeactivateActCtx(0, cookie);

            if(status == 0)
            {
                path = pPath->Buffer;
            }
            else
            {
                RtlFreeUnicodeString(&DllName2);

                path.append(L".dll");
                SetLastError(RtlNtStatusToDosError(status));
                return RtlNtStatusToDosError(status);
            }

            RtlFreeUnicodeString(&DllName2);

            SetLastError(ERROR_SUCCESS);
            return ERROR_SUCCESS;
        }

        HMODULE CMemModules::GetModuleAddress( const char* modname, bool skipManualModules/* = false*/, const wchar_t* baseModule /*= L""*/ )
        {
            wchar_t wPath[MAX_PATH] = {0};

            MultiByteToWideChar(CP_ACP, 0, modname, (int)strlen(modname), wPath, MAX_PATH);

            return GetModuleAddress(wPath, skipManualModules, baseModule);
        }

        HMODULE CMemModules::GetModuleAddress( const wchar_t* modname, bool skipManualModules /*= false*/, const wchar_t* baseModule /*= L""*/ )
        {
            HANDLE snapshot         = 0;
            MODULEENTRY32 mod       = {sizeof(MODULEENTRY32), 0};
            wchar_t wPath[MAX_PATH] = {0};
            wchar_t wBase[MAX_PATH] = {0};

            if( !modname )
                return 0;

            wcscpy_s(wPath, MAX_PATH, modname);
            wcscpy_s(wBase, MAX_PATH, baseModule);
            PathStripPathW(wPath);
            PathStripPathW(wBase);

            std::wstring wName(wPath);

            ResolvePath(wName, ApiSchemaOnly, wBase);

            if(!skipManualModules)
            {
                auto iter = ms_modules.find(wName);
                if(iter != ms_modules.end())
                    return iter->second;
            }

            if((snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, m_memory.m_pid)) == INVALID_HANDLE_VALUE)
                return 0;

            if(Module32First(snapshot, &mod))
            {
                if( _wcsicmp(mod.szModule, wName.c_str()) == 0 )
                {
                    CloseHandle(snapshot);
                    return (HMODULE)mod.modBaseAddr;
                }

                while( Module32Next(snapshot, &mod) )
                {
                    if( _wcsicmp(mod.szModule, wName.c_str()) == 0 )
                    {
                        CloseHandle(snapshot);
                        return (HMODULE)mod.modBaseAddr;
                    }
                }

                CloseHandle(snapshot);
                return 0;
            }
            else
            {
                CloseHandle(snapshot);
                return 0;
            }
        }

        FARPROC CMemModules::GetProcAddressEx( HMODULE hMod, const char* name, const wchar_t* baseModule /*= L"" */ )
        {
            std::unique_ptr<IMAGE_EXPORT_DIRECTORY> expData;

            IMAGE_DOS_HEADER hdrDos  = {0};
            IMAGE_NT_HEADERS hdrNt32 = {0};
            DWORD            expSize = 0;
            size_t           expBase = 0;
            void            *pFunc   = nullptr;

            m_memory.Read((void*)hMod, sizeof(hdrDos), &hdrDos);

            if(hdrDos.e_magic != IMAGE_DOS_SIGNATURE)
                return NULL;

            m_memory.Read((BYTE*)hMod + hdrDos.e_lfanew, sizeof(hdrNt32), &hdrNt32);

            if(hdrNt32.Signature != IMAGE_NT_SIGNATURE)
                return NULL;

            expBase = hdrNt32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

            if(expBase)
            {
                expSize = hdrNt32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
                expData.reset((IMAGE_EXPORT_DIRECTORY*)new uint8_t[expSize]());

                m_memory.Read((uint8_t*)hMod + expBase, expSize, expData.get());

                WORD  *pAddressOfOrds   = (WORD*)(expData->AddressOfNameOrdinals + (size_t)expData.get() - expBase); 
                DWORD *pAddressOfNames  = (DWORD*)(expData->AddressOfNames       + (size_t)expData.get() - expBase);
                DWORD *pAddressOfFuncs  = (DWORD*)(expData->AddressOfFunctions   + (size_t)expData.get() - expBase);

                for( DWORD i = 0; i < expData->NumberOfFunctions; ++i )
                {
                    WORD OrdIndex   = 0xFFFF;
                    char *pName     = nullptr;

                    if((size_t)name <= 0xFFFF)
                    {
                        OrdIndex = (WORD)i;
                    }
                    else if((size_t)name > 0xFFFF && i < expData->NumberOfNames)
                    {
                        pName       = (char*)(pAddressOfNames[i] + (size_t)expData.get() - expBase);            
                        OrdIndex    = (WORD)pAddressOfOrds[i];
                    }
                    else
                        return 0;

                    if(((size_t)name <= 0xFFFF && (WORD)name == (OrdIndex + expData->Base)) || ((size_t)name > 0xFFFF && strcmp(pName, name) == 0))
                    {
                        pFunc = (void*)(pAddressOfFuncs[OrdIndex] + (size_t)hMod);

                        if((size_t)pFunc >= (size_t)hMod + expBase && (size_t)pFunc <= (size_t)hMod + expBase + expSize)
                        {
                            char forwardStr[255] = {0};

                            m_memory.Read(pFunc, sizeof(forwardStr), forwardStr);

                            std::string chainExp(forwardStr);

                            std::string strDll  = chainExp.substr(0, chainExp.find(".")) + ".dll";
                            std::string strName = chainExp.substr(chainExp.find(".") + 1, strName.npos);

                            HMODULE hChainMod = GetModuleAddress(strDll.c_str(), false, baseModule);

                            if(hChainMod == NULL)
                                hChainMod = SimpleInject(strDll);

                            if(strName.find("#") == 0)
                                return GetProcAddressEx(hChainMod, (const char*)atoi(strName.c_str() + 1));
                            else
                                return GetProcAddressEx(hChainMod, strName.c_str());
                        }

                        break;
                    }
                }
            }

            return (FARPROC)pFunc;
        }

        bool CMemModules::InitApiSchema()
        {
            if(!m_ApiSchemaMap.empty())
                return true;

            ApiSchemaMapHeader* pHeader = *(ApiSchemaMapHeader**)((uint8_t*)(NtCurrentTeb()->ProcessEnvironmentBlock) + 0x8 + 0xC * WordSize);
            ApiSchemaModuleEntry *pEntries = (ApiSchemaModuleEntry *)(pHeader + 1);

            for (DWORD i = 0; i < pHeader->NumModules; i++)
            {
                ApiSchemaModuleEntry *pEntry = pEntries + i;
                std::vector<std::wstring> vhosts;

                wchar_t apiName[MAX_PATH] = {0};
                wchar_t dllName[MAX_PATH] = {0};

                memcpy(apiName, (uint8_t*)pHeader + pEntry->OffsetToName, pEntry->NameSize);
                swprintf_s(dllName, MAX_PATH, L"API-%s.dll", apiName);
                std::transform(dllName, dllName + MAX_PATH, dllName, ::tolower);

                ApiSchemaModuleHostsHeader* pHostHeader = (ApiSchemaModuleHostsHeader*)((uint8_t*)pHeader + pEntry->OffsetOfHosts);
                ApiSchemaModuleHost* pHosts = (ApiSchemaModuleHost*)(pHostHeader + 1);

                for (DWORD j = 0; j < pHostHeader->NumHosts; j++)
                {
                    ApiSchemaModuleHost *pHost = pHosts + j;

                    std::wstring hostName((wchar_t*)((uint8_t*)pHeader + pHost->OffsetOfHostName), pHost->HostNameSize / sizeof(wchar_t));

                    if(!hostName.empty())
                        vhosts.push_back(hostName);
                }

                m_ApiSchemaMap.insert(std::make_pair(dllName, vhosts));
            }

            return true;
        }

        std::wstring CMemModules::GetProcessDirectory()
        {
            HANDLE snapshot   = 0;
            MODULEENTRY32 mod = {sizeof(MODULEENTRY32), 0};
            std::wstring path = L"";

            if((snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, m_memory.m_pid)) == INVALID_HANDLE_VALUE )
                return L"";

            if(Module32First(snapshot, &mod))
                path = mod.szExePath;

            CloseHandle(snapshot);

            return path;
        }

        void CMemModules::AddManualModule(const std::wstring& name, HMODULE base)
        {
            std::wstring name2(name);
            std::transform(name2.begin(), name2.end(), name2.begin(), ::tolower);

            ms_modules.emplace(std::make_pair(name2, base));
        }

        void CMemModules::RemoveManualModule( const std::wstring& name )
        {
            std::wstring name2(name);
            std::transform(name2.begin(), name2.end(), name2.begin(), ::tolower);

            if(ms_modules.count(name2))
                ms_modules.erase(name2);
        }

        void CMemModules::PushLocalActx( HANDLE hActx /*= INVALID_HANDLE_VALUE*/ )
        {
            m_ActxStack.push(hActx);
        }

        void CMemModules::PopLocalActx()
        {
            m_ActxStack.pop();
        }
    }
}
