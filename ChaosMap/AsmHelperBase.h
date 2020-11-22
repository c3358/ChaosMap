#pragma once

#include "stdafx.h"

#pragma warning( disable : 4100 4244 4245 4127 )

#include "AsmJit/AsmJit/Assembler.h"
#include "AsmJit/AsmJit/MemoryManager.h"

#pragma warning( default : 4100 4244 4245 4127 )

namespace ds_mmap
{
    #define WordSize sizeof(size_t)

    struct GenVar
    {
        enum eType
        {
            reg,
            imm,
            imm_double,
            imm_float,
            mem,
            mem_ptr
        };

        eType         type;             
        AsmJit::GPReg reg_val;          
        AsmJit::Mem   mem_val;          

        union 
        {
            size_t    imm_val;          
            double    imm_double_val;   
            float     imm_float_val;    
        } ;
        
        GenVar(size_t _imm)
            : type(imm)
            , imm_val(_imm)
        {
        }

        explicit GenVar(double _imm_fpu)
            : type(imm_double)
            , imm_double_val(_imm_fpu)
        {
        }

        explicit GenVar(float _imm_fpu)
            : type(imm_float)
            , imm_float_val(_imm_fpu)
        {
        }

        GenVar(const AsmJit::GPReg& _reg)
            : type(reg)
            , reg_val(_reg)
            , imm_double_val(-1.0)
        {
        }

        GenVar(const AsmJit::Mem& _mem)
            : type(mem)
            , mem_val(_mem)
            , imm_double_val(-1.0)
        {
        }

        explicit GenVar(AsmJit::Mem* _mem)
            : type(mem_ptr)
            , mem_val(*_mem)
            , imm_double_val(-1.0)
        {
        }

        inline eType  getType()       const { return type; }
        inline size_t getImm()        const { return imm_val; }
        inline size_t getImm_float()  const { return *(uint32_t*)&imm_float_val; }
        inline size_t getImm_double() const { return *(size_t*)&imm_double_val; }

        inline const AsmJit::GPReg& getReg() const { return reg_val; }
        inline const AsmJit::Mem&   getMem() const { return mem_val; }
    };

    enum eCalligConvention
    {
        CC_cdecl,
        CC_stdcall,
        CC_thiscall,
        CC_fastcall
    };

    enum eArgType
    {
        AT_ecx,
        AT_edx,
        AT_stack,
    };

    class CAsmHelperBase
    {
    public:
        CAsmHelperBase(AsmJit::Assembler& _a);
        ~CAsmHelperBase(void);

        virtual void GenPrologue() = 0;

        virtual void GenEpilogue( int retSize = WordSize ) = 0;

        virtual void GenCall(void* pFN, std::initializer_list<GenVar> args, eCalligConvention cc = CC_stdcall) = 0;

        virtual void ExitThreadWithStatus() = 0;

        virtual void SaveRetValAndSignalEvent() = 0;

    protected:
        AsmJit::Assembler& a;
        CAsmHelperBase& operator=(const CAsmHelperBase& other);
    };

    #ifdef _M_AMD64
    #define AsmJitHelper CAsmHelper64
    #else
    #define AsmJitHelper CAsmHelper32
    #endif
}