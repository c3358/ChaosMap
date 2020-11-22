#include "PEManger.h"

namespace ds_mmap
{
    namespace ds_pe
    {
        CPEManger::CPEManger(void)
            : m_pFileBase(nullptr)
            , m_pImageHdr(nullptr)
            , m_isPlainData(false)
        {
        }

        CPEManger::~CPEManger(void)
        {
        }

        bool CPEManger::Parse( const void* pFileBase, bool isPlainData )
        {
            const IMAGE_DOS_HEADER        *pDosHdr    = nullptr;
            const IMAGE_SECTION_HEADER    *pSection   = nullptr;

            if(!pFileBase)
            {
                SetLastError(err::pe::NoFile);
                return false;
            }

            m_isPlainData = isPlainData;

            m_pFileBase = pFileBase;
            pDosHdr   = (const IMAGE_DOS_HEADER*)(m_pFileBase);

            if(pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
            {
                SetLastError(err::pe::NoSignature);
                return false;
            }

            m_pImageHdr = (const IMAGE_NT_HEADERS*)((uint8_t*)pDosHdr + pDosHdr->e_lfanew);

            if(m_pImageHdr->Signature != IMAGE_NT_SIGNATURE)
            {
                SetLastError(err::pe::NoSignature);
                return false;
            }

            pSection = (const IMAGE_SECTION_HEADER*)((uint8_t*)m_pImageHdr + sizeof(IMAGE_NT_HEADERS));

            for(int i = 0; i < m_pImageHdr->FileHeader.NumberOfSections; ++i, pSection++)
                m_sections.push_back(*pSection);

            return true;
        }

        size_t CPEManger::DirectoryAddress( int index ) const
        {
            if(m_pImageHdr->OptionalHeader.DataDirectory[index].VirtualAddress == 0)
                return 0;
            else
                return ResolveRvaToVA(m_pImageHdr->OptionalHeader.DataDirectory[index].VirtualAddress);
        }

        size_t CPEManger::ResolveRvaToVA( size_t Rva ) const
        {
            if(m_isPlainData)
                return (size_t)ImageRvaToVa((PIMAGE_NT_HEADERS)m_pImageHdr, (PVOID)m_pFileBase, (ULONG)Rva, NULL);
            else
                return (size_t)m_pFileBase + Rva;
        }

        size_t CPEManger::DirectorySize( int index ) const
        {
            if(m_pImageHdr->OptionalHeader.DataDirectory[index].VirtualAddress == 0)
                return 0;
            else
                return (size_t)m_pImageHdr->OptionalHeader.DataDirectory[index].Size;
        }

        const std::vector<IMAGE_SECTION_HEADER>& CPEManger::Sections() const
        {
            return m_sections;
        }

        int CPEManger::GetTLSCallbacks( const void* targetBase, std::vector<void*>& result ) const
        {
            IMAGE_TLS_DIRECTORY *pTls = (IMAGE_TLS_DIRECTORY*)DirectoryAddress(IMAGE_DIRECTORY_ENTRY_TLS);
            size_t* pCallback = nullptr;

            if(!pTls)
                return 0;

            if(m_pImageHdr->OptionalHeader.ImageBase != (size_t)m_pFileBase)
                pCallback = (size_t*)REBASE(pTls->AddressOfCallBacks, m_pImageHdr->OptionalHeader.ImageBase, m_pFileBase);
            else
                pCallback = (size_t*)pTls->AddressOfCallBacks;

            for(; *pCallback; pCallback++)
                result.push_back((void*)REBASE(*pCallback, m_pImageHdr->OptionalHeader.ImageBase, targetBase));

            return (int)result.size();
        }

        size_t CPEManger::ImageSize() const
        {
            return m_pImageHdr->OptionalHeader.SizeOfImage;
        }

        size_t CPEManger::HeadersSize() const
        {
            return m_pImageHdr->OptionalHeader.SizeOfHeaders;
        }

        size_t CPEManger::ImageBase() const
        {
            return m_pImageHdr->OptionalHeader.ImageBase;
        }

        const void* CPEManger::EntryPoint( const void* base ) const
        {
            return (const void*)((size_t)base + m_pImageHdr->OptionalHeader.AddressOfEntryPoint);
        }

        bool CPEManger::IsPureManaged() const
        {
            IMAGE_COR20_HEADER *pCorHdr = (IMAGE_COR20_HEADER*)DirectoryAddress(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);

            if(pCorHdr)
            {
                if(pCorHdr->Flags & COMIMAGE_FLAGS_ILONLY)
                    return true;
            }

            return false;
        }

        bool CPEManger::IsExe() const
        {
            return !(m_pImageHdr->FileHeader.Characteristics & IMAGE_FILE_DLL);
        }
    }
}