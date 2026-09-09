package fi.gekkio.ghidraboy;

import java.util.*;

/** Bounded relational rows at a control point; rows contain domains, never predecessor histories. */
final class PredicatedJoin {
  private PredicatedJoin() {}
  record Domain(List<AbstractValues.Origin> roots, List<List<Long>> assignments) {
    Domain { roots=List.copyOf(roots); assignments=assignments.stream().map(List::copyOf).toList(); }
    static Domain unknown() { return new Domain(List.of(),List.of(List.of())); }
  }
  record Part(Domain domain, Map<Long,AbstractValues.Value> registers, int taken) {}
  static AbstractValues.Value fold(AbstractValues.Value value) {
    return value.values()!=null&&value.values().size()==1 ? AbstractValues.constant(value.values().first(),value.width()) : value;
  }
  static AbstractValues.Value restrict(AbstractValues.Value value,Domain domain) {
    value=fold(value);
    if(value.origin().kind()!=AbstractValues.OriginKind.OPERATION||domain.roots().isEmpty())return value;
    var roots=new LinkedHashSet<AbstractValues.Origin>();AbstractValues.roots(value.origin(),roots);
    if(roots.size()>1&&Collections.disjoint(roots,domain.roots()))return value;
    return compact(value,domain);
  }
  /** Conditional byte truth table normalization. Unsupported larger relations retain their origin. */
  static AbstractValues.Value compact(AbstractValues.Value value,Domain domain) {
    value=fold(value);if(value.width()!=1||value.origin().kind()!=AbstractValues.OriginKind.OPERATION)return value;
    var valueRoots=new LinkedHashSet<AbstractValues.Origin>();AbstractValues.roots(value.origin(),valueRoots);
    var columnsInDomain=new ArrayList<Integer>();for(int i=0;i<domain.roots().size();i++)if(valueRoots.contains(domain.roots().get(i)))columnsInDomain.add(i);
    var originalDomain=domain;
    domain=new Domain(columnsInDomain.stream().map(originalDomain.roots()::get).toList(),originalDomain.assignments().stream().map(row->columnsInDomain.stream().map(row::get).toList()).distinct().toList());
    var roots=new LinkedHashSet<>(domain.roots());roots.addAll(valueRoots);
    var ordered=new ArrayList<>(roots);long cases=domain.assignments().size();
    for(int i=domain.roots().size();i<ordered.size();i++) {
      if(ordered.get(i).width()!=1||cases>AbstractValues.MAX_INPUT_CASES/256)return value;cases*=256;
    }
    var tuples=new ArrayList<List<Long>>(domain.assignments());
    for(int i=domain.roots().size();i<ordered.size();i++) {
      var next=new ArrayList<List<Long>>();for(var old:tuples)for(long v=0;v<256;v++){var row=new ArrayList<>(old);row.add(v);next.add(row);}tuples=next;
    }
    var results=new ArrayList<Long>();long[] work={0};
    for(var tuple:tuples) {
      var assignment=new HashMap<AbstractValues.Origin,Long>();for(int i=0;i<ordered.size();i++)assignment.put(ordered.get(i),tuple.get(i));
      Long result=AbstractValues.concrete(value.origin(),assignment,new HashMap<>(),work);if(result==null)return value;results.add(result);
    }
    if(results.stream().distinct().limit(2).count()==1)return AbstractValues.constant(results.getFirst(),1);
    var columns=new ArrayList<Integer>();for(int i=0;i<ordered.size();i++)columns.add(i);
    for(int column=ordered.size()-1;column>=0;column--) {
      var candidate=new ArrayList<>(columns);candidate.remove(Integer.valueOf(column));var function=new HashMap<List<Long>,Long>();boolean independent=true;
      for(int row=0;row<tuples.size();row++) {
        var tuple=tuples.get(row);var key=candidate.stream().map(tuple::get).toList();var old=function.putIfAbsent(key,results.get(row));
        if(old!=null&&!old.equals(results.get(row))){independent=false;break;}
      }
      if(independent)columns=candidate;
    }
    if(columns.size()!=1)return value;
    int column=columns.getFirst();var function=new TreeMap<Long,Long>();for(int i=0;i<tuples.size();i++)function.put(tuples.get(i).get(column),results.get(i));
    // Common byte flag transport: retain a bounded structural mask/origin, not a 256-row table.
    if(function.size()==256) {
      long base=function.get(0L),mask=0;for(int bit=0;bit<8;bit++)if((function.get(1L<<bit)^base)==(1L<<bit))mask|=1L<<bit;
      boolean matches=true;for(var e:function.entrySet())if(((e.getKey()&mask)|base)!=e.getValue()){matches=false;break;}
      if(matches) {
        var input=new AbstractValues.Value(1,new AbstractValues.Top("scoped join input",false),ordered.get(column),AbstractValues.Role.BYTE_VALUE,new TreeSet<>(function.keySet()),List.of());
        return fold(AbstractValues.evaluate(ghidra.program.model.pcode.PcodeOp.INT_OR,1,List.of(
            AbstractValues.evaluate(ghidra.program.model.pcode.PcodeOp.INT_AND,1,List.of(input,AbstractValues.constant(mask,1)),"join bit projection"),AbstractValues.constant(base,1)),"join bit projection"));
      }
    }
    if(function.size()==256) {
      var rows=new ArrayList<AbstractValues.TableRow>();for(var e:function.entrySet())rows.add(new AbstractValues.TableRow(List.of(e.getKey()),e.getValue(),"complete byte relation"));
      return AbstractValues.table(1,List.of(ordered.get(column)),rows,"complete join projection");
    }
    return value;
  }
  static List<Part> split(AbstractValues.Storage storage,AbstractValues.Value condition,Domain domain) {
    condition=compact(condition,domain);
    if(condition.values()!=null&&condition.values().size()==1) {
      long taken=condition.values().first();
      if(taken!=0&&taken!=1)throw new IllegalArgumentException("Nonboolean branch condition");
      return List.of(new Part(domain,new TreeMap<>(storage.registers),(int)taken));
    }
    var roots=new LinkedHashSet<>(domain.roots());AbstractValues.roots(condition.origin(),roots);
    var ordered=new ArrayList<>(roots);long count=domain.assignments().size();
    for(int i=domain.roots().size();i<ordered.size();i++) {
      if(ordered.get(i).width()!=1||count>AbstractValues.MAX_INPUT_CASES/256)throw new IllegalArgumentException("Incomplete join branch input relation");
      count*=256;
    }
    var assignments=new ArrayList<List<Long>>(domain.assignments());
    for(int i=domain.roots().size();i<ordered.size();i++) {
      var expanded=new ArrayList<List<Long>>();
      for(var old:assignments)for(long v=0;v<256;v++){var next=new ArrayList<>(old);next.add(v);expanded.add(next);}
      assignments=expanded;
    }
    var slots=new ArrayList<Long>();
    for(var e:new TreeMap<>(storage.registers).entrySet()) {
      var dependencies=new LinkedHashSet<AbstractValues.Origin>();AbstractValues.roots(e.getValue().origin(),dependencies);
      if(roots.containsAll(dependencies))slots.add(e.getKey());
    }
    var groups=new LinkedHashMap<List<Long>,List<List<Long>>>();long[] work={0};
    for(var assignment:assignments) {
      var inputs=new HashMap<AbstractValues.Origin,Long>();for(int i=0;i<ordered.size();i++)inputs.put(ordered.get(i),assignment.get(i));
      var memo=new HashMap<AbstractValues.Origin,Long>();var tuple=new ArrayList<Long>();
      tuple.add(AbstractValues.concrete(condition.origin(),inputs,memo,work));
      for(long slot:slots)tuple.add(AbstractValues.concrete(storage.registers.get(slot).origin(),inputs,memo,work));
      if(tuple.stream().anyMatch(Objects::isNull))throw new IllegalArgumentException("Incomplete join predicate/value relation");
      if(tuple.get(0)!=0&&tuple.get(0)!=1)throw new IllegalArgumentException("Nonboolean branch relation");
      groups.computeIfAbsent(List.copyOf(tuple),k->new ArrayList<>()).add(assignment);
    }
    var parts=new ArrayList<Part>();
    for(var group:groups.entrySet()) {
      var registers=new TreeMap<>(storage.registers);
      for(int i=0;i<slots.size();i++)registers.put(slots.get(i),AbstractValues.constant(group.getKey().get(i+1),1));
      parts.add(new Part(new Domain(ordered,group.getValue()),registers,group.getKey().getFirst().intValue()));
    }
    return parts;
  }
}
