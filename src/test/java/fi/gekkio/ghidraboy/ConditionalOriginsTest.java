package fi.gekkio.ghidraboy;

import static org.junit.jupiter.api.Assertions.*;
import ghidra.program.model.pcode.PcodeOp;
import java.util.*;
import org.junit.jupiter.api.Test;

class ConditionalOriginsTest {
  private AbstractValues.Value op(int code,int width,AbstractValues.Value... values) {
    return AbstractValues.canonical(AbstractValues.evaluate(code,width,List.of(values),"conditional normalization witness"));
  }
  @Test void pushPopReassemblyPreservesBothInputByteDefinitions() {
    var lo=AbstractValues.input("frame","low",0,1);var hi=AbstractValues.input("frame","high",0,1);
    var word=op(PcodeOp.INT_OR,2,op(PcodeOp.INT_ZEXT,2,lo),op(PcodeOp.INT_LEFT,2,op(PcodeOp.INT_ZEXT,2,hi),AbstractValues.constant(8,4)));
    assertEquals(lo.origin(),op(PcodeOp.SUBPIECE,1,word,AbstractValues.constant(0,4)).origin());
    assertEquals(hi.origin(),op(PcodeOp.SUBPIECE,1,word,AbstractValues.constant(1,4)).origin());
  }
  @Test void overwrittenFlagBitsDoNotRetainUnrelatedInputs() {
    var unknown=AbstractValues.input("frame","SP",0,2);
    var carry=op(PcodeOp.INT_CARRY,1,unknown,AbstractValues.constant(4,2));
    var flags=op(PcodeOp.INT_LEFT,1,carry,AbstractValues.constant(4,4));
    flags=op(PcodeOp.INT_AND,1,flags,AbstractValues.constant(0xef,1));
    assertEquals(AbstractValues.constant(0,1).origin(),flags.origin());
    var zero=op(PcodeOp.INT_OR,1,flags,AbstractValues.constant(0x80,1));
    assertEquals(AbstractValues.constant(0x80,1).origin(),zero.origin());
  }
  @Test void normalizedBitSlicesRetainTheCompleteIndependentRelation() {
    var x=AbstractValues.input("mask","byte",0,1);
    for(int shift=0;shift<8;shift++)for(int mask:List.of(0,1,0x0f,0x80,0xf0,0xff)) {
      var raw=AbstractValues.evaluate(PcodeOp.INT_AND,1,List.of(AbstractValues.evaluate(PcodeOp.INT_LEFT,1,List.of(x,AbstractValues.constant(shift,4)),"raw shift"),AbstractValues.constant(mask,1)),"raw mask");
      var normalized=AbstractValues.canonical(raw);
      var relation=AbstractValues.relation(List.of(x.origin(),raw.origin(),normalized.origin()));
      assertTrue(relation.complete());assertEquals(256,relation.reachable().size());
      for(var row:relation.reachable()){long input=row.values().get(0);long expected=((input<<shift)&255)&mask;assertEquals(expected,row.values().get(1));assertEquals(expected,row.values().get(2));}
    }
  }
}
