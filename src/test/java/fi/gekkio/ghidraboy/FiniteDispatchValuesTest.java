package fi.gekkio.ghidraboy;

import static org.junit.jupiter.api.Assertions.*;
import ghidra.program.model.pcode.PcodeOp;
import java.util.*;
import org.junit.jupiter.api.Test;

class FiniteDispatchValuesTest {
  @Test void guardedPartialReadDoesNotInventDefaultRows() {
    var u=AbstractValues.input("fixture","actual-byte",0,1);
    var guard=AbstractValues.evaluate(PcodeOp.INT_LESS,1,List.of(u,AbstractValues.constant(3,1)),"guard");
    var condition=new AbstractValues.Condition(List.of(new AbstractValues.Term(guard.origin(),1)));
    var table=AbstractValues.table(1,List.of(u.origin()),List.of(new AbstractValues.TableRow(List.of(0L),7,"r0"),new AbstractValues.TableRow(List.of(1L),9,"r1"),new AbstractValues.TableRow(List.of(2L),11,"r2")),"read");
    assertFalse(AbstractValues.relation(List.of(table.origin())).complete());
    var relation=AbstractValues.relation(List.of(table.origin()),condition);
    assertTrue(relation.complete());assertEquals(List.of(List.of(7L),List.of(9L),List.of(11L)),relation.reachable().stream().map(AbstractValues.Tuple::values).toList());
    var exits=new ArrayList<AbstractValues.Condition>();
    exits.add(new AbstractValues.Condition(List.of(new AbstractValues.Term(guard.origin(),0))));
    for(long value:List.of(7L,9L,11L))exits.add(new AbstractValues.Condition(List.of(new AbstractValues.Term(guard.origin(),1),new AbstractValues.Term(table.origin(),value))));
    assertTrue(AbstractValues.covers(exits));exits.removeLast();assertFalse(AbstractValues.covers(exits));
  }
  @Test void zeroAndShiftDomainsAreCompleteDistinctFromEmpty() {
    var u=AbstractValues.input("fixture","actual-byte",0,1);
    var zero=AbstractValues.evaluate(PcodeOp.INT_AND,1,List.of(u,AbstractValues.constant(0,1)),"raw AND");
    assertEquals(Set.of(0L),zero.values());assertEquals(1,AbstractValues.relation(List.of(zero.origin())).reachable().size());
    var shift=AbstractValues.evaluate(PcodeOp.INT_RIGHT,1,List.of(u,AbstractValues.constant(1,1)),"raw SRL");
    assertEquals(128,shift.values().size());assertEquals(0L,shift.values().first());assertEquals(127L,shift.values().last());
    var impossible=new AbstractValues.Condition(List.of(new AbstractValues.Term(zero.origin(),1)));
    var empty=AbstractValues.relation(List.of(zero.origin()),impossible);assertTrue(empty.complete());assertTrue(empty.reachable().isEmpty());
  }
}
