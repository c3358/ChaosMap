#pragma once

#include "stdafx.h"
#include "MemCore.h"
#include "PEManger.h"

#define FIELD_OFFSET2(type, field)  ((LONG)(LONG_PTR)&(((type)0)->field))
#define GET_FIELD_PTR(entry, field) (void*)((uint8_t*)entry + FIELD_OFFSET2(decltype(entry), field))

extern "C"
NTSYSAPI 
NTSTATUS 
NTAPI 
RtlDosApplyFileIsolationRedirection_Ustr(IN ULONG Flags,
                                         IN PUNICODE_STRING OriginalName,
                                         IN PUNICODE_STRING Extension,
                                         IN OUT PUNICODE_STRING StaticString,
                                         IN OUT PUNICODE_STRING DynamicString,
                                         IN OUT PUNICODE_STRING *NewName,
                                         IN PULONG  NewFlags,
                                         IN PSIZE_T FileNameSize,
                                         IN PSIZE_T RequiredLength);    

extern "C"
NTSYSAPI 
NTSTATUS 
NTAPI 
RtlHashUnicodeString(_In_   PCUNICODE_STRING String,
                     _In_   BOOLEAN CaseInSensitive,
                     _In_   ULONG HashAlgorithm,
                     _Out_  PULONG HashValue );

extern "C"
NTSYSAPI 
WCHAR 
NTAPI 
RtlUpcaseUnicodeChar( WCHAR chr );

extern "C" 
NTSYSAPI 
PVOID 
NTAPI 
RtlEncodeSystemPointer( IN PVOID Pointer );

extern "C" 
NTSYSAPI 
PVOID 
NTAPI 
RtlRbInsertNodeEx( IN PVOID Root, IN PVOID Parent, IN BOOL InsertRight, IN _RTL_BALANCED_NODE* Link );

namespace ds_mmap
{
    namespace ds_process
    {
        class CNtLdr
        {
        public:
            CNtLdr(CMemCore& memory);
            ~CNtLdr(void);

            /*
                Initialize some loader stuff
            */
            bool Init();

            bool CreateNTReference(HMODULE hMod, size_t ImageSize, const std::wstring& DllBaseName, const std::wstring& DllBasePath);

            bool AddStaticTLSEntry(void* pModule);

            bool InsertInvertedFunctionTable( void* ModuleBase, size_t ImageSize );

            void* LdrpInvertedFunctionTable() const { return m_LdrpInvertedFunctionTable; }

        private:

            bool FindLdrpHashTable();

            bool FindLdrpModuleIndexBase();

            bool FindLdrpModuleBase();

            bool PatternSearch();

            bool FindLdrHeap();

            _LDR_DATA_TABLE_ENTRY_W8* InitW8Node( void* ModuleBase, size_t ImageSize, const std::wstring& dllname, const std::wstring& dllpath, ULONG& outHash );
            _LDR_DATA_TABLE_ENTRY_W7* InitW7Node( void* ModuleBase, size_t ImageSize, const std::wstring& dllname, const std::wstring& dllpath, ULONG& outHash );

            void InsertTreeNode( _LDR_DATA_TABLE_ENTRY_W8* pParentNode, _LDR_DATA_TABLE_ENTRY_W8* pNode, bool bLeft = false );

            void InsertHashNode( PLIST_ENTRY pNodeLink, ULONG hash );

			void InsertMemModuleNode( PLIST_ENTRY pNodeMemoryOrderLink, PLIST_ENTRY pNodeLoadOrderLink );

            VOID InsertTailList( PLIST_ENTRY ListHead, PLIST_ENTRY Entry );

            template<typename T> 
            T* SetNode(T* ptr, void* pModule);

            inline bool IsWin8orHigher() const { return (m_verinfo.dwMajorVersion >= 6 && m_verinfo.dwMinorVersion >= 2); }

            CNtLdr& operator =( const CNtLdr& other );
        private:
            CMemCore&       m_memory;                           
            OSVERSIONINFO   m_verinfo;                          
            size_t          m_LdrpHashTable;                    
            size_t          m_LdrpModuleIndexBase;              // LdrpModuleIndex address
            size_t          m_LdrpModuleBase;                   // PEB->Ldr->InLoadOrderModuleList address
            size_t          m_LdrHeapBase;                      // Loader heap base address
            void           *m_LdrpHandleTlsData;                // LdrpHandleTlsData address
            void           *m_LdrpInvertedFunctionTable;        // LdrpInvertedFunctionTable address
            void           *m_RtlInsertInvertedFunctionTable;   // RtlInsertInvertedFunctionTable address

            std::map<HMODULE, void*> m_nodeMap;                 // Map of allocated native structures
        };
    }
}