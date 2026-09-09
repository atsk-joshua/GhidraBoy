package fi.gekkio.ghidraboy;

import static org.junit.jupiter.api.Assertions.*;
import ghidra.program.model.pcode.PcodeOp;
import java.util.*;
import org.junit.jupiter.api.Test;

class AbstractValuesTest {
  AbstractValues.Value b = AbstractValues.input("program/entry", "entry-register-byte", 3, 1);
  AbstractValues.Value d = AbstractValues.input("program/entry", "entry-register-byte", 5, 1);
  AbstractValues.Value op(int opcode, int width, AbstractValues.Value... args) {
    return AbstractValues.evaluate(opcode, width, List.of(args), "diagnostic-site");
  }
  @Test void partialBitsNarrowToCompleteFiniteCover() {
    var high = op(PcodeOp.INT_OR, 1, b, AbstractValues.constant(0x80,1));
    var bits = assertInstanceOf(AbstractValues.PartialBits.class, high.domain());
    assertEquals(0x80, bits.knownMask()); assertEquals(0x80, bits.knownValue());
    var low = op(PcodeOp.INT_AND,1,high,AbstractValues.constant(3,1));
    assertEquals(new TreeSet<>(List.of(0L,1L,2L,3L)),low.values());
    assertEquals(4,low.alternatives().size());
    assertTrue(low.alternatives().stream().allMatch(a -> a.condition().terms().get(0).origin().equals(low.origin())));
    assertTrue(AbstractValues.relation(List.of(low.origin())).complete());
  }
  @Test void pureStructureIgnoresSitesButPreservesInputAndDefinitionIdentity() {
    var one=AbstractValues.constant(1,1);
    var first=AbstractValues.evaluate(PcodeOp.INT_AND,1,List.of(b,one),"0150");
    var second=AbstractValues.evaluate(PcodeOp.INT_AND,1,List.of(b,one),"0160");
    assertEquals(first.origin(),second.origin()); assertNotEquals(first.sites(),second.sites());
    assertNotEquals(b.origin(),d.origin());
    assertNotEquals(b.origin(),AbstractValues.input("other-program/entry","entry-register-byte",3,1).origin());
    assertEquals(b.origin(),op(PcodeOp.COPY,1,b).origin());
    assertNotEquals(b.origin(),op(PcodeOp.INT_ADD,1,b,one).origin());
    assertInstanceOf(AbstractValues.Top.class,b.domain());
    assertNotEquals(op(PcodeOp.COPY,1,b).origin(),op(PcodeOp.COPY,1,d).origin());
  }
  @Test void commonRootIsNeitherEqualityNorIndependence() {
    var bit0=op(PcodeOp.INT_AND,1,b,AbstractValues.constant(1,1));
    var bit1=op(PcodeOp.INT_AND,1,op(PcodeOp.INT_RIGHT,1,b,AbstractValues.constant(1,1)),AbstractValues.constant(1,1));
    var joint=AbstractValues.relation(List.of(bit0.origin(),bit1.origin()));
    assertTrue(joint.complete());
    assertEquals(List.of(List.of(0L,0L),List.of(0L,1L),List.of(1L,0L),List.of(1L,1L)),joint.reachable().stream().map(AbstractValues.Tuple::values).toList());
    var same=AbstractValues.relation(List.of(bit0.origin(),bit0.origin()));
    assertEquals(List.of(List.of(0L,0L),List.of(1L,1L)),same.reachable().stream().map(AbstractValues.Tuple::values).toList());
    assertEquals(AbstractValues.Compatibility.UNSAT,AbstractValues.compatible(new AbstractValues.Condition(List.of(
        new AbstractValues.Term(bit0.origin(),0),new AbstractValues.Term(bit0.origin(),1)))));
  }
  @Test void widthsSignedExtensionTruncationAndBudgetReasonsRemainExplicit() {
    assertEquals(0L,op(PcodeOp.INT_ADD,2,AbstractValues.constant(65535,2),AbstractValues.constant(1,2)).values().first());
    assertEquals(65535L,op(PcodeOp.INT_SEXT,2,AbstractValues.constant(255,1)).values().first());
    assertEquals(255L,op(PcodeOp.INT_ZEXT,2,AbstractValues.constant(255,1)).values().first());
    var wide=op(PcodeOp.PIECE,2,b,d);
    assertNull(wide.values());
    var exhausted=assertInstanceOf(AbstractValues.Top.class,wide.domain());
    assertTrue(exhausted.enumerationIncomplete()); assertTrue(exhausted.reason().contains("budget"));
    var third=AbstractValues.input("program/entry","entry-register-byte",7,1);
    var condition=new AbstractValues.Condition(List.of(new AbstractValues.Term(b.origin(),0),new AbstractValues.Term(d.origin(),0),new AbstractValues.Term(third.origin(),0)));
    assertEquals(AbstractValues.Compatibility.UNKNOWN,AbstractValues.compatible(condition));
  }
  @Test void singletonTableRetainsPhysicalOriginAndRoleIsSeparate() {
    var value=AbstractValues.table(1,List.of(),List.of(new AbstractValues.TableRow(List.of(),7,"ROM2:2000=7")),"0150");
    assertInstanceOf(AbstractValues.Exact.class,value.domain());
    assertNotEquals(AbstractValues.constant(7,1).origin(),value.origin());
    assertEquals(value.origin(),value.as(AbstractValues.Role.MAPPER_SELECTOR).origin());
    assertEquals(value.domain(),value.as(AbstractValues.Role.CPU_POINTER).domain());
  }
  @Test void originGrowthRefusesBeforeUnboundedRecursion() {
    assertThrows(IllegalArgumentException.class, () -> {
      var value = b;
      for (int i=0;i<200;i++) value = op(PcodeOp.INT_NEGATE,1,value);
    });
  }
}
