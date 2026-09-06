// Self-authored regression exercising the native implementation, not a duplicate model.
#include "architecture.hh"
#include "funcdata.hh"
#include "jumptable.hh"
#include "test.hh"

namespace ghidra {
class RightBoundProbe : public JumpBasic {
public:
  RightBoundProbe(void) : JumpBasic((JumpTable *)0) {}
  using JumpBasic::getMaxValue;
  using JumpBasic::getStride;
  using JumpBasic::calcRange;
};
class RightBoundEnvironment {
  Architecture *architecture;
  uintb nextAddress;
public:
  RightBoundEnvironment(void) : architecture((Architecture *)0), nextAddress(0x1000) {}
  ~RightBoundEnvironment(void) { delete architecture; }
  Funcdata *function(void) {
    if (architecture == (Architecture *)0) {
      ArchitectureCapability *capability = ArchitectureCapability::getCapability("xml");
      istringstream input("<binaryimage arch=\"x86:LE:64:default:gcc\"></binaryimage>");
      DocumentStorage store;
      Document *doc = store.parseDocument(input);
      store.registerTag(doc->getRoot());
      architecture = capability->buildArchitecture("", "", &cout);
      architecture->init(store);
    }
    Address address(architecture->getDefaultCodeSpace(),nextAddress);
    nextAddress += 0x100;
    Funcdata *fd = architecture->symboltab->getGlobalScope()->addFunction(address,"bound")->getFunction();
    fd->setHighLevel();
    return fd;
  }
};
static RightBoundEnvironment rightBoundEnvironment;

static Varnode *makeBoundOperation(Funcdata *fd,int4 inputSize,int4 outputSize,OpCode opcode,uintb amount,bool constant)
{
  // Construct an isolated straight-line block with an unconstrained input.
  BlockBasic *block = const_cast<BlockGraph &>(fd->getBasicBlocks()).newBlockBasic(fd);
  PcodeOp *op = fd->newOp(2,fd->getAddress());
  fd->opSetOpcode(op,opcode);
  fd->opSetInput(op,fd->newUnique(inputSize),0);
  fd->opSetInput(op,constant ? fd->newConstant(8,amount) : fd->newUnique(8),1);
  Varnode *output = fd->newUniqueOut(outputSize,op);
  fd->opInsertEnd(op,block);
  return output;
}

TEST(jump_logical_right_immediate_bound)
{
  for(int4 size : {1,2,4,8}) {
    uintb bits = 8 * size;
    for(uintb shift : {uintb(0),uintb(1),uintb(4),bits-1,bits,bits+1,~uintb(0)}) {
      Funcdata *fd = rightBoundEnvironment.function();
      Varnode *vn = makeBoundOperation(fd,size,size,CPUI_INT_RIGHT,shift,true);
      // No NZMask pass: the bound must follow from the immediate operation alone.
      uintb expected = shift == 0 ? 0 : shift >= bits ? 1 : uintb(1) << (bits-shift);
      ASSERT_EQUALS(RightBoundProbe::getMaxValue(vn),expected);
      fd->calcNZMask();
      if(shift >= bits) {
        ASSERT_EQUALS(vn->getNZMask(),uintb(0));
        ASSERT_EQUALS(RightBoundProbe::getStride(vn),32);
        RightBoundProbe probe;
        CircleRange range;
        probe.calcRange(vn,range);
        ASSERT_EQUALS(range.getSize(),uintb(1));
        ASSERT(range.contains(uintb(0)));
        ASSERT(!range.contains(uintb(1)));
      }
    }
  }
}

TEST(jump_logical_right_negative_cases)
{
  Funcdata *fd = rightBoundEnvironment.function();
  ASSERT_EQUALS(RightBoundProbe::getMaxValue(makeBoundOperation(fd,1,1,CPUI_INT_SRIGHT,4,true)),uintb(0));
  ASSERT_EQUALS(RightBoundProbe::getMaxValue(makeBoundOperation(fd,1,1,CPUI_INT_RIGHT,4,false)),uintb(0));
  ASSERT_EQUALS(RightBoundProbe::getMaxValue(makeBoundOperation(fd,2,1,CPUI_INT_RIGHT,4,true)),uintb(0));
  ASSERT_EQUALS(RightBoundProbe::getMaxValue(makeBoundOperation(fd,16,16,CPUI_INT_RIGHT,4,true)),uintb(0));
}

TEST(jump_zero_mask_stride_singleton)
{
  Funcdata *fd = rightBoundEnvironment.function();
  Varnode *vn = makeBoundOperation(fd,1,1,CPUI_INT_AND,0,true);
  fd->calcNZMask();
  ASSERT_EQUALS(vn->getNZMask(),uintb(0));
  ASSERT_EQUALS(RightBoundProbe::getStride(vn),32);
  RightBoundProbe probe;
  CircleRange range;
  probe.calcRange(vn,range);
  ASSERT_EQUALS(range.getSize(),uintb(1));
  ASSERT(range.contains(uintb(0)));
  ASSERT(!range.contains(uintb(1)));
}
} // namespace ghidra
