#pragma once

#include "FileProjection.h"
#include "PEManger.h"
#include "Process.h"
#include "ImageNET.h"

#include <map>

namespace ds_mmap
{
    typedef BOOL (APIENTRY *pDllMain)(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);

    enum eLoadFlags
    {
        NoFlags         = 0x00,
        ManualImports   = 0x01,
        CreateLdrRef    = 0x02,
        UnlinkVAD       = 0x04,
        RebaseProcess   = 0x20,

        NoExceptions    = 0x01000,
        PartialExcept   = 0x02000,
        NoDelayLoad     = 0x04000,
        NoSxS           = 0x08000,
        NoTLS           = 0x10000,
    };


    struct ImageContext
    {
        CFileProjection      Image;           // Image file mapping
        ds_pe::CPEManger     ImagePE;         // PE parser
        eLoadFlags           flags;           // Image loader flags
        void                *pTargetBase;     // Target image base address
        size_t               pExpTableAddr;   // Exception table address (amd64 only)
        std::vector<void*>   tlsCallbacks;    // TLS callback routines
        std::tr2::sys::wpath FilePath;        // path to image being mapped
        std::wstring         FileName;        // File name string
        pDllMain             EntryPoint;      // Target image entry point

        ImageContext()
            : flags(NoFlags)
            , pTargetBase(nullptr)
            , pExpTableAddr(0)
            , FilePath(L"")
            , EntryPoint(nullptr)
        {
        }

        ~ImageContext()
        {
        }
    };

    typedef std::vector<std::unique_ptr<ImageContext>> vecImageCtx;

    //
    // Image mapper
    //
    class CBlackMMap
    {
        
    public:
        CBlackMMap(DWORD pid);
        ~CBlackMMap(void);

        HMODULE MapDll( const std::wstring& path, eLoadFlags flags = NoFlags );
        HMODULE MapDll( const std::string&  path, eLoadFlags flags = NoFlags );

        bool UnmapAllModules();

        FARPROC GetProcAddressEx(HMODULE mod, const char* procName);

        bool CallFunction(void* pFn, std::initializer_list<GenVar> args, size_t& result,  eCalligConvention cc = CC_cdecl, HANDLE hContextThread = INVALID_HANDLE_VALUE);
        
    private:

        HMODULE MapPureManaged();

        bool CopyImage();

        bool ProtectImageMemory();

        bool RelocateImage();

        bool ResolveImport();

        bool ResolveDelayImport();

        bool InitStaticTLS();

        bool RunTLSInitializers(DWORD dwReason);

        bool CallEntryPoint(DWORD dwReason);

        bool EnableExceptions();

        bool DisableExceptions();

        bool CreateActx(int id = 2);

        bool FreeActx();

        bool InitializeCookie();

        DWORD GetSectionProt(DWORD characteristics);

    private:
        vecImageCtx             m_Images;           // Mapped images
        ImageContext           *m_pTopImage;        // Image context information 
        ds_process::CProcess    m_TargetProcess;    // Target process manager
        int                     m_tlsIndex;         // Current static TLS index
        void                   *m_pAContext;        // SxS activation context memory address
    };
}

