#include "MemCore.h"

namespace ds_mmap
{
    namespace ds_process
    {
        CMemCore::CMemCore(void)
            : m_hProcess(NULL)
            , m_hMainThd(NULL)
            , m_pid(0)
            , m_hWorkThd(NULL)
            , m_hWaitEvent(NULL)
            , m_pWorkerCode(nullptr)
            , m_pCodecave(nullptr)
            , m_codeSize(0)
        {
        }

        CMemCore::~CMemCore(void)
        {
            TerminateWorkerThread();

            if(m_hProcess)
                CloseHandle(m_hProcess);

            if(m_hMainThd)
                CloseHandle(m_hMainThd);

            if(m_pCodecave)
                Free(m_pCodecave);

            FreeAll();
        }

        DWORD CMemCore::Allocate( size_t size, PVOID &pAddr )
        {
            SetLastError(ERROR_SUCCESS);

            void* pTmp = VirtualAllocEx(m_hProcess, pAddr, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if(!pTmp)
            {
                pTmp = VirtualAllocEx(m_hProcess, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                if(pTmp)
                {
                    pAddr = pTmp;
                    m_Allocations.emplace_back(pTmp);
                    SetLastError(ERROR_IMAGE_NOT_AT_BASE);
                }
            }
            else
            {
                pAddr = pTmp;
                m_Allocations.emplace_back(pAddr);            
            }

            return GetLastError();
        }

        DWORD CMemCore::Free( PVOID pAddr )
        {
            SetLastError(ERROR_SUCCESS);
            VirtualFreeEx(m_hProcess, pAddr, 0, MEM_RELEASE);

            auto iter = std::find(m_Allocations.begin(), m_Allocations.end(), pAddr);

            if(iter != m_Allocations.end())
                m_Allocations.erase(iter);

            return GetLastError();
        }

        void CMemCore::FreeAll()
        {
            for(auto& pAddr : m_Allocations)
                VirtualFreeEx(m_hProcess, pAddr, 0, MEM_RELEASE);

            m_Allocations.clear();
        }

        DWORD CMemCore::Protect( PVOID pAddr, size_t size, DWORD flProtect, DWORD *pOld /*= NULL*/ )
        {
            DWORD dwOld = 0;

            SetLastError(ERROR_SUCCESS);

            VirtualProtectEx(m_hProcess, pAddr, size, flProtect, &dwOld);

            if(pOld)
                *pOld = dwOld;

            return GetLastError();
        }

        DWORD CMemCore::Read( void* dwAddress, size_t dwSize, PVOID pResult )
        {
            SIZE_T dwRead = 0;

            if(dwAddress == 0)
                return ERROR_INVALID_ADDRESS;

            if(!ReadProcessMemory(m_hProcess, (LPCVOID)dwAddress, pResult, dwSize, &dwRead) || dwRead != dwSize)
                return GetLastError();

            return ERROR_SUCCESS;
        }

        DWORD CMemCore::Write( void* pAddress, size_t dwSize, const void* pData )
        {
            SIZE_T dwWritten = 0;

            if(pAddress == NULL)
            {
                SetLastError(ERROR_INVALID_ADDRESS);
                return ERROR_INVALID_ADDRESS;
            }

            if(!WriteProcessMemory(m_hProcess, pAddress, pData, dwSize, &dwWritten) || dwWritten != dwSize)
                return GetLastError();

            return ERROR_SUCCESS;
        }

        DWORD CMemCore::RemoteCall( PVOID pCode, size_t size, size_t& callResult, PVOID pArg /*= NULL*/ )
        {
            if(!m_pCodecave)
            {
                if(Allocate(size, m_pCodecave) != ERROR_SUCCESS)
                    return GetLastError();

                m_codeSize = size;
            }
            else if(size > m_codeSize)
            {
                Free(m_pCodecave);
                m_pCodecave = nullptr;

                if(Allocate(size, m_pCodecave) != ERROR_SUCCESS)
                    return GetLastError();

                m_codeSize = size;
            }

            if(Write(m_pCodecave, size, pCode) != ERROR_SUCCESS)
                return GetLastError();
    
            return RemoteCallDirect(m_pCodecave, pArg, callResult);
        }

        DWORD CMemCore::RemoteCallDirect( PVOID pProc, PVOID pArg, size_t& callResult, bool waitForReturn /*= true */ )
        {
            DWORD dwResult    = ERROR_SUCCESS;
            HANDLE hThread    = NULL;

            callResult  = 0xFFFFFFF0;
            hThread     = CreateRemoteThread(m_hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pProc, pArg, 0, NULL);

            if (hThread && waitForReturn)
            {
                WaitForSingleObject(hThread, INFINITE);

                GetExitCodeThread(hThread, (LPDWORD)&callResult);
            }

            return dwResult;
        }

        DWORD CMemCore::CreateWorkerThread()
        {
            AsmJit::Assembler a;
            AsmJitHelper ah(a);
            AsmJit::Label l_loop = a.newLabel();
            DWORD thdID = 0;
            int space   = 4 * WordSize;

            if(!m_hWorkThd)
            {
                ah.GenPrologue();

                a.bind(l_loop);
                ah.GenCall(&SleepEx, { 5, TRUE });
                a.jmp(l_loop);

                ah.ExitThreadWithStatus();
                ah.GenEpilogue();

                if(Write((uint8_t*)m_pWorkerCode + space, a.getCodeSize(), a.make()) != ERROR_SUCCESS)
                {
                    if(m_pWorkerCode)
                    {
                        Free(m_pWorkerCode);
                        m_pWorkerCode = nullptr;
                    }

                    return 0;
                }

                m_hWorkThd = CreateRemoteThread(m_hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((uint8_t*)m_pWorkerCode + space), m_pWorkerCode, 0, &thdID);

                return thdID;
            }
            else
                return GetThreadId(m_hWorkThd);            
        }

        bool CMemCore::CreateAPCEvent( DWORD threadID )
        {         
            if(m_hWaitEvent == NULL)
            {
                AsmJit::Assembler a;
                AsmJitHelper ah(a);

                size_t dwResult        = ERROR_SUCCESS;
                void *pCodecave        = NULL;
                wchar_t pEventName[64] = {0};
                size_t len             =  sizeof(pEventName);

                swprintf_s(pEventName, ARRAYSIZE(pEventName), L"_MMapEvent_0x%x_0x%x", threadID, GetTickCount());

                Allocate(a.getCodeSize() + len, pCodecave);

                ah.GenPrologue();
                ah.GenCall(&CreateEventW, { NULL, TRUE, FALSE, (size_t)pCodecave });

            #ifdef _M_AMD64
                a.mov(AsmJit::ndx, AsmJit::qword_ptr(AsmJit::nsp, WordSize));
            #else
                a.mov(AsmJit::ndx, AsmJit::dword_ptr(AsmJit::nbp, 2 * WordSize));
            #endif   

                a.mov(sysint_ptr(AsmJit::ndx, WordSize), AsmJit::nax);

                ah.ExitThreadWithStatus();
                ah.GenEpilogue();

                if(Write((uint8_t*)pCodecave + len, a.getCodeSize(), a.make()) != ERROR_SUCCESS ||
                    Write((uint8_t*)pCodecave, len, pEventName) != ERROR_SUCCESS)
                {
                    if(pCodecave)
                        Free(pCodecave);

                    return false;
                }

                RemoteCallDirect((uint8_t*)pCodecave + len, m_pWorkerCode, dwResult);

                m_hWaitEvent = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, pEventName);

                if(pCodecave)
                    Free(pCodecave);

                if(dwResult == NULL || m_hWaitEvent == NULL)
                {
                    SetLastError(ERROR_OBJECT_NOT_FOUND);
                    return false;
                }
            }

            return true;
        }

        DWORD CMemCore::CreateRPCEnvironment( bool noThread /*= false*/ )
        {
            DWORD dwResult = ERROR_SUCCESS;
            DWORD thdID    = 1337;
            bool status    = true;

            if(m_pWorkerCode == nullptr)
                Allocate(0x1000, m_pWorkerCode);

            if(noThread == false)
                thdID = CreateWorkerThread();

            status = CreateAPCEvent(thdID);
             
            if(thdID == 0 || status == false)
                dwResult = GetLastError();

            return dwResult;
        }

        DWORD CMemCore::PrepareCodecave( PVOID pCode, size_t size )
        {
            if(!m_pCodecave)
            { 
                m_codeSize = (size > 0x1000) ? size : 0x1000;

                if(Allocate(m_codeSize, m_pCodecave) != ERROR_SUCCESS)
                {
                    m_codeSize = 0;
                    return GetLastError();
                }
            }

            else if(size > m_codeSize)
            {
                Free(m_pCodecave);
                m_pCodecave = nullptr;

                if(Allocate(size, m_pCodecave) != ERROR_SUCCESS)
                    return GetLastError();

                m_codeSize = size;
            }

            if(Write(m_pCodecave, size, pCode) != ERROR_SUCCESS)
                return GetLastError();

            return ERROR_SUCCESS;
        }

        DWORD CMemCore::TerminateWorkerThread()
        {
            if(m_hWaitEvent)
            {
                CloseHandle(m_hWaitEvent);
                m_hWaitEvent = NULL;
            }

            if(m_hWorkThd)
            {
                BOOL res   = TerminateThread(m_hWorkThd, 0);
                m_hWorkThd = NULL;

                if(m_pWorkerCode)
                {
                    Free(m_pWorkerCode);
                    m_pWorkerCode = nullptr;
                }

                return res == TRUE;
            }
            else
                return ERROR_SUCCESS;
        }

        DWORD CMemCore::ExecInWorkerThread( PVOID pCode, size_t size, size_t& callResult )
        {
            DWORD dwResult = ERROR_SUCCESS;

            dwResult = PrepareCodecave(pCode, size);
            if(dwResult != ERROR_SUCCESS)
                return dwResult;

            if(!m_hWorkThd)
                CreateRPCEnvironment();

            if(m_hWaitEvent)
                ResetEvent(m_hWaitEvent);

            if(QueueUserAPC((PAPCFUNC)m_pCodecave, m_hWorkThd, (ULONG_PTR)m_pWorkerCode))
            {
                dwResult   = WaitForSingleObject(m_hWaitEvent, INFINITE);
                callResult = Read<size_t>(m_pWorkerCode);
            }

            Sleep(0);

            return dwResult;
        }

        DWORD CMemCore::ExecInAnyThread( PVOID pCode, size_t size, size_t& callResult, HANDLE hThread /*= NULL */ )
        {
            DWORD dwResult = ERROR_SUCCESS;
            CONTEXT ctx    = {0};

            if(hThread == NULL)
                hThread = m_hMainThd;

            dwResult = PrepareCodecave(pCode, size);
            if(dwResult != ERROR_SUCCESS)
                return dwResult;

            if(m_hWaitEvent)
                ResetEvent(m_hWaitEvent);

            SuspendThread(hThread);

            ctx.ContextFlags = CONTEXT_FULL;

            if(GetThreadContext(hThread, &ctx))
            {
                AsmJit::Assembler a;
                AsmJitHelper ah(a);

            #ifdef _M_AMD64
                const int count      = 15;
                AsmJit::GPReg regs[] = { AsmJit::rax, AsmJit::rbx, AsmJit::rcx, AsmJit::rdx, AsmJit::rsi, 
                                         AsmJit::rdi, AsmJit::r8,  AsmJit::r9,  AsmJit::r10, AsmJit::r11, 
                                         AsmJit::r12, AsmJit::r13, AsmJit::r14, AsmJit::r15, AsmJit::rbp };
                
                a.sub(AsmJit::rsp, 15 * WordSize);  
                a.pushfq();                          

                for(int i = 0; i < count; i++)
                     a.mov(AsmJit::Mem(AsmJit::rsp, i * WordSize), regs[i]);

                ah.GenCall(m_pCodecave, { (size_t)m_pWorkerCode });

                for(int i = 0; i < count; i++)
                    a.mov(regs[i], AsmJit::Mem(AsmJit::rsp, i * WordSize));

                a.popfq();
                a.add(AsmJit::rsp, count * WordSize);

                a.jmp(ctx.Rip);
            #else
                a.pushad();
                a.pushfd();
                ah.GenCall(m_pCodecave, { (size_t)m_pWorkerCode });
                a.popfd();
                a.popad();
                a.push(ctx.Eip);
                a.ret();
            #endif
                
                if(Write((uint8_t*)m_pCodecave + size, a.getCodeSize(), a.make()) == ERROR_SUCCESS)
                {
                #ifdef _M_AMD64
                    ctx.Rip = (size_t)m_pCodecave + size;
                #else
                    ctx.Eip = (size_t)m_pCodecave + size;
                #endif

                    if(!SetThreadContext(hThread, &ctx))
                        dwResult = GetLastError();
                }
                else
                    dwResult = GetLastError();
            }
            else
                dwResult = GetLastError();

            ResumeThread(hThread);
            
            if(dwResult == ERROR_SUCCESS)
            {
                dwResult   = WaitForSingleObject(m_hWaitEvent, INFINITE);
                callResult = Read<size_t>(m_pWorkerCode);
            }

            return dwResult;
        }

        size_t CMemCore::FindPattern( const std::string& sig, const std::string& pattern, void* scanStart, size_t scanSize, std::vector<size_t>& out )
        {
            bool fullMatch = false;
            uint8_t *pBuffer = (uint8_t*)VirtualAlloc(NULL, scanSize, MEM_COMMIT, PAGE_READWRITE);

            out.clear();

            if(pattern.length() > sig.length())
                return 0;

            if(pattern.find('?') == pattern.npos)
                fullMatch = true;

            if(pBuffer && Read(scanStart, scanSize, pBuffer) == ERROR_SUCCESS)
            {
                size_t length = pattern.length();

                for(size_t x = 0; x < scanSize - length; x++ )
                {
                    bool bMatch = true;

                    if(fullMatch)
                        bMatch = (memcmp(sig.data(), pBuffer + x, length) == 0);
                    else
                        for(size_t i = 0; i < length; i++)
                        {
                            if(pattern[i] == 'x' && ((char*)(pBuffer + x))[i] != sig[i])
                            {
                                bMatch = false;
                                break;
                            }
                        }

                    if(bMatch)
                        out.emplace_back((size_t)scanStart + x);
                }                
            }

            if(pBuffer)
                VirtualFree(pBuffer, 0, MEM_DECOMMIT);

            return out.size();
        }

        PPEB CMemCore::GetPebBase()
        {
            PROCESS_BASIC_INFORMATION pbi = {0};
            ULONG bytes = 0;

            NtQueryInformationProcess(m_hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &bytes);

            return pbi.PebBaseAddress;
        }

        PTEB CMemCore::GetTebBase(HANDLE hThread /*= 0*/)
        {
            THREAD_BASIC_INFORMATION tbi = {0};    
            ULONG bytes = 0;

            if(hThread == NULL)
                hThread = m_hMainThd;

            NtQueryInformationThread(hThread, (THREADINFOCLASS)0, &tbi, sizeof(tbi), &bytes);

            return tbi.TebBaseAddress;
        }

    }
}