#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_os_ostream.h"
#include "llvm/IR/PatternMatch.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

using namespace llvm;
using namespace PatternMatch;

namespace
{

    struct YANSO_VM_Combination : public llvm::FunctionPass
    {
        static char ID;

        YANSO_VM_Combination() : llvm::FunctionPass(ID) {}

        bool runOnFunction(llvm::Function &F) override;

    private:
        void printFunctionDeclaration(llvm::Function &F);
    };

} // namespace

void YANSO_VM_Combination::printFunctionDeclaration(llvm::Function &F)
{
    llvm::errs() << "Function " << F.getName() << "(";
    llvm::Function::arg_iterator AI;
    llvm::Function::arg_iterator AE;

    unsigned idx = 0;
    for (AI = F.arg_begin(), AE = F.arg_end();
         AI != AE;
         AI++)
    {
        AI->getType()->print(llvm::errs());
        llvm::errs() << " %" << AI->getName();

        if (idx < F.getArgumentList().size() - 1)
            llvm::errs() << ",";
        idx++;
    }
    llvm::errs() << ")\n";
    if (F.isDeclaration())
        llvm::errs() << " has " << F.size() << " basic blocks.\n";
}

bool YANSO_VM_Combination::runOnFunction(llvm::Function &F)
{
    bool modified = false;
    int line = 1;
    BinaryOperator *newII = nullptr;

    for (inst_iterator I = inst_begin(&F), E = inst_end(&F); I != E; ++I)
    {
        if (BinaryOperator *II = dyn_cast<BinaryOperator>(&*I))
        {
            switch (II->getOpcode())
            {
            case BinaryOperator::Add:
            {
                Value *LHS = II->getOperand(0);
                Value *RHS = II->getOperand(1);

                Value *A, *B;

                // (A|~B) + (~A&B) - (~(A&B)) + (A|B) -> A+B
                if (match(RHS, m_Or(m_Value(A), m_Value(B))) &&
                    match(LHS,
                          m_Sub(m_Add(m_Or(m_Not(m_Value(B)),
                                           m_Value(A)),
                                      m_And(m_Not(m_Value(A)),
                                            m_Value(B))),
                                m_Not(m_And(m_Value(A), m_Value(B))))))
                {
                    llvm::errs() << "YANSOLLVM_VM_Add found in line " << line << " from: ";
                    printFunctionDeclaration(F);
                    Function::arg_iterator itArgs = F.arg_begin();
                    Value *x = dyn_cast<Value>(itArgs);
                    Value *y = dyn_cast<Value>(++itArgs);

                    newII = llvm::BinaryOperator::Create(BinaryOperator::Add, x, y);
                    ReplaceInstWithInst(II, newII);
                    modified = true;
                }
                break;
            }
            case BinaryOperator::Sub:
            {
                Value *LHS = II->getOperand(0);
                Value *RHS = II->getOperand(1);

                Value *A, *B;

                // (~A|B) + (A&~B) - (~(A&B)) -> A & B
                if (match(RHS, m_Not(m_And(m_Value(A), m_Value(B)))) &&
                    match(LHS, m_Add(m_Or(m_Not(m_Value(A)), m_Value(B)), m_And(m_Value(A), m_Not(m_Value(B))))))
                {
                    llvm::errs() << "YANSOLLVM_VM_And found in line " << line << " from: ";
                    printFunctionDeclaration(F);

                    Function::arg_iterator itArgs = F.arg_begin();
                    Value *x = dyn_cast<Value>(itArgs);
                    Value *y = dyn_cast<Value>(++itArgs);

                    newII = llvm::BinaryOperator::Create(BinaryOperator::And, x, y);
                    ReplaceInstWithInst(II, newII);
                    modified = true;
                }

                // (A^B) + B - (~A&B) -> A | B
                if (match(RHS, m_And(m_Not(m_Value(A)), m_Value(B))) &&
                    match(LHS, m_Add(m_Xor(m_Value(A), m_Value(B)), m_Value(B))))
                {
                    llvm::errs() << "YANSOLLVM_VM_Sub found in line " << line << " from: ";
                    printFunctionDeclaration(F);

                    Function::arg_iterator itArgs = F.arg_begin();
                    Value *x = dyn_cast<Value>(itArgs);
                    Value *y = dyn_cast<Value>(++itArgs);

                    newII = llvm::BinaryOperator::Create(BinaryOperator::Or, x, y);
                    ReplaceInstWithInst(II, newII);
                    modified = true;
                }

                break;
            }
            default:
                break;
            }
        }

        if (modified)
            break;
        line++;
    }

    return modified;
}

char YANSO_VM_Combination::ID = 0;

static llvm::RegisterPass<YANSO_VM_Combination> X(
    "yansovmsimplify",
    "Combine instructions from YANSO LLVM VM obfuscation",
    false,
    false);