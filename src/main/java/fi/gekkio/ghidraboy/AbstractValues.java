package fi.gekkio.ghidraboy;

import ghidra.pcode.opbehavior.BinaryOpBehavior;
import ghidra.pcode.opbehavior.OpBehaviorFactory;
import ghidra.pcode.opbehavior.UnaryOpBehavior;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import java.util.*;

/** Internal straight-line value boundary for producers and future graph adapters. No mapper or memory model. */
final class AbstractValues {
  private AbstractValues() {}
  static final int MAX_VALUES = 256, MAX_ORIGIN_NODES = 4096, MAX_CANDIDATES = 4096;
  static final long MAX_INPUT_CASES = 65536, MAX_RELATION_WORK = 4194304;
  enum Role { CPU_POINTER, MAPPER_SELECTOR, BYTE_VALUE }
  enum OriginKind { INPUT, CONSTANT, OPERATION }
  enum Compatibility { SAT, UNSAT, UNKNOWN }
  sealed interface Domain permits Exact, Finite, PartialBits, Top {}
  record Exact(long value) implements Domain {}
  record Finite(List<Long> values) implements Domain { Finite { values = List.copyOf(values); } }
  record PartialBits(long knownMask, long knownValue) implements Domain {}
  record Top(String reason, boolean enumerationIncomplete) implements Domain {}
  record TableRow(List<Long> keys, long value, String physicalSources) {
    TableRow { keys = List.copyOf(keys); }
  }
  /** Sites are deliberately not identity. Input definitions include authority/storage slices. */
  record Origin(OriginKind kind, int width, String input, long constant, int opcode,
      List<Origin> inputs, List<TableRow> table) {
    Origin { inputs = List.copyOf(inputs); table = List.copyOf(table); }
  }
  record Term(Origin origin, long value) {}
  record Condition(List<Term> terms) { Condition { terms = List.copyOf(terms); } }
  record Alternative(long value, Condition condition) {}
  record Value(int width, Domain domain, Origin origin, Role role, NavigableSet<Long> values, List<String> sites) {
    Value { values = values == null ? null : Collections.unmodifiableNavigableSet(new TreeSet<>(values)); sites = List.copyOf(sites); }
    Value as(Role next) { return new Value(width, domain, origin, next, values, sites); }
    String expression() { return describe(origin); } // diagnostic only; never relation authority
    List<Alternative> alternatives() {
      if (values == null) return List.of();
      return values.stream().map(v -> new Alternative(v, new Condition(List.of(new Term(origin, v))))).toList();
    }
  }
  record Tuple(List<Long> values, Condition condition) { Tuple { values = List.copyOf(values); } }
  record Relation(boolean complete, String reason, long inputCases, List<Tuple> reachable) {
    Relation { reachable = List.copyOf(reachable); }
  }
  static long truncate(long value, int width) { return width == 8 ? value : value & ((1L << (width * 8)) - 1); }
  private static int nodes(Origin origin) {
    record Pending(Origin origin, int depth) {}
    var pending = new ArrayDeque<Pending>(); pending.add(new Pending(origin, 1)); int count = 0;
    while (!pending.isEmpty()) {
      var next = pending.removeLast();
      if (next.depth() > 128 || (count += 1 + next.origin().table().size()) > MAX_ORIGIN_NODES) return MAX_ORIGIN_NODES + 1;
      for (var child : next.origin().inputs()) pending.add(new Pending(child, next.depth() + 1));
    }
    return count;
  }
  private static Origin operation(int opcode, int width, List<Origin> inputs, List<TableRow> table) {
    var origin = new Origin(OriginKind.OPERATION, width, null, 0, opcode, inputs, table);
    if (nodes(origin) > MAX_ORIGIN_NODES) throw new IllegalArgumentException("Abstract value origin/condition growth budget exhausted");
    return origin;
  }
  static String describe(Origin o) {
    if (o.kind() == OriginKind.INPUT) return o.input();
    if (o.kind() == OriginKind.CONSTANT) return "const" + o.width() + "(" + o.constant() + ")";
    return (o.opcode() == -1 ? "immutable-read" : PcodeOp.getMnemonic(o.opcode())) + "[" + o.width() + "](" +
        String.join(",", o.inputs().stream().map(AbstractValues::describe).toList()) + ")";
  }
  private static Value value(int width, NavigableSet<Long> cover, Origin origin, List<String> sites, String reason) {
    Domain domain;
    if (cover == null) domain = new Top(reason, true);
    else if (cover.size() == 1) domain = new Exact(cover.first());
    else {
      long ones = truncate(-1, width), zeros = ones;
      for (long v : cover) { ones &= v; zeros &= ~v; }
      long mask = truncate(ones | zeros, width);
      domain = cover.size() >= 128 && mask != 0 ? new PartialBits(mask, ones)
          : width == 1 && cover.size() == 256 ? new Top(reason, false) : new Finite(new ArrayList<>(cover));
    }
    return new Value(width, domain, origin, Role.BYTE_VALUE, cover, sites);
  }
  static Value input(String scope, String storage, long offset, int width) {
    var o = new Origin(OriginKind.INPUT, width, scope + ":" + storage + "@" + offset, 0, 0, List.of(), List.of());
    TreeSet<Long> cover = null;
    if (width == 1) { cover = new TreeSet<>(); for (long v = 0; v < 256; v++) cover.add(v); }
    return new Value(width, new Top("unknown scoped input", false), o, Role.BYTE_VALUE, cover, List.of());
  }
  static Value constant(long n, int width) {
    long v = truncate(n, width);
    return value(width, new TreeSet<>(List.of(v)), new Origin(OriginKind.CONSTANT, width, null, v, 0, List.of(), List.of()), List.of(), "constant");
  }
  private static Long apply(int opcode, int width, List<Origin> origins, List<Long> args) {
    if (args.stream().anyMatch(Objects::isNull)) return null;
    if (opcode == PcodeOp.COPY) return truncate(args.get(0), width);
    if (!(opcode >= PcodeOp.INT_EQUAL && opcode <= PcodeOp.BOOL_OR)
        && opcode != PcodeOp.PIECE && opcode != PcodeOp.SUBPIECE
        && opcode != PcodeOp.POPCOUNT && opcode != PcodeOp.LZCOUNT) return null;
    var behavior = OpBehaviorFactory.getOpBehavior(opcode);
    try {
      if (behavior instanceof UnaryOpBehavior unary && args.size() == 1)
        return truncate(unary.evaluateUnary(width, origins.get(0).width(), args.get(0)), width);
      if (behavior instanceof BinaryOpBehavior binary && args.size() == 2) {
        int sizein = origins.get(0).width(); long a = args.get(0), b = args.get(1);
        if (opcode == PcodeOp.PIECE) { sizein = origins.get(1).width(); if (width != origins.get(0).width() + sizein) return null; }
        if (b == 0 && (opcode == PcodeOp.INT_DIV || opcode == PcodeOp.INT_SDIV || opcode == PcodeOp.INT_REM || opcode == PcodeOp.INT_SREM)) return null;
        if (opcode == PcodeOp.SUBPIECE && (b < 0 || b > sizein || width > sizein - b)) return null;
        return truncate(binary.evaluateBinary(width, sizein, a, b), width);
      }
    } catch (ArithmeticException ignored) { return null; }
    return null;
  }
  private static List<String> sites(List<Value> inputs, String site) {
    var sites = new LinkedHashSet<String>();
    for (var input : inputs) sites.addAll(input.sites());
    sites.add(site);
    if (sites.size() > MAX_ORIGIN_NODES) throw new IllegalArgumentException("Abstract diagnostic provenance budget exhausted");
    return List.copyOf(sites);
  }
  static Value evaluate(int opcode, int width, List<Value> inputs, String site) {
    var provenance = sites(inputs, site);
    var origins = inputs.stream().map(Value::origin).toList();
    // Equal-width copies preserve source definition identity, including Top.
    if (opcode == PcodeOp.COPY && inputs.size() == 1 && width == inputs.get(0).width()) {
      var v = inputs.get(0); return new Value(width, v.domain(), v.origin(), v.role(), v.values(), provenance);
    }
    var origin = operation(opcode, width, origins, List.of());
    if (width < 1 || width > 8 || inputs.isEmpty() || inputs.size() > 2 || inputs.stream().anyMatch(v -> v.values() == null))
      return value(width, null, origin, provenance, "unsupported/incomplete operation inputs");
    var result = new TreeSet<Long>();
    for (long a : inputs.get(0).values()) {
      for (long b : inputs.size() == 1 ? List.of(0L) : inputs.get(1).values()) {
        var n = apply(opcode, width, origins, inputs.size() == 1 ? List.of(a) : List.of(a, b));
        if (n == null) return value(width, null, origin, provenance, "unsupported operation semantics");
        result.add(n);
        if (result.size() > MAX_VALUES) return value(width, null, origin, provenance, "enumeration budget exhausted; not mathematical Top");
      }
    }
    return value(width, result, origin, provenance, "complete byte cover");
  }
  /** Local expression normalization for conditional frames; retains input identities and sites. */
  static Value canonical(Value v) {
    Origin o=canonicalOrigin(v.origin());
    if(o.kind()==OriginKind.CONSTANT)return new Value(v.width(),new Exact(o.constant()),o,v.role(),new TreeSet<>(List.of(o.constant())),v.sites());
    if(o.kind()==OriginKind.INPUT&&o.width()==1){var cover=new TreeSet<Long>();for(long n=0;n<256;n++)cover.add(n);return new Value(v.width(),new Top("preserved input byte",false),o,v.role(),cover,v.sites());}
    return new Value(v.width(),v.domain(),o,v.role(),v.values(),v.sites());
  }
  private static Origin canonicalOrigin(Origin o) {
    if(o.kind()!=OriginKind.OPERATION)return o;
    var in=o.inputs().stream().map(AbstractValues::canonicalOrigin).toList();
    if(o.opcode()==PcodeOp.SUBPIECE&&in.get(1).kind()==OriginKind.CONSTANT) {
      Origin whole=in.get(0);int offset=(int)in.get(1).constant();
      if(offset==0&&o.width()==whole.width())return whole;
      if(whole.kind()==OriginKind.OPERATION&&(whole.opcode()==PcodeOp.INT_OR||whole.opcode()==PcodeOp.INT_AND)) {
        var pieces=whole.inputs().stream().map(x->canonicalOrigin(new Origin(OriginKind.OPERATION,o.width(),null,0,PcodeOp.SUBPIECE,List.of(x,constant(offset,1).origin()),List.of()))).toList();
        return canonicalOrigin(new Origin(OriginKind.OPERATION,o.width(),null,0,whole.opcode(),pieces,List.of()));
      }
      if((whole.opcode()==PcodeOp.INT_LEFT||whole.opcode()==PcodeOp.INT_RIGHT)&&whole.inputs().get(1).kind()==OriginKind.CONSTANT&&whole.inputs().get(1).constant()%8==0) {
        int bytes=(int)whole.inputs().get(1).constant()/8;var child=whole.inputs().get(0);
        if(whole.opcode()==PcodeOp.INT_LEFT&&offset+o.width()<=bytes)return constant(0,o.width()).origin();
        int relative=whole.opcode()==PcodeOp.INT_LEFT?offset-bytes:offset+bytes;
        if(relative>=0&&relative+o.width()<=child.width())return canonicalOrigin(new Origin(OriginKind.OPERATION,o.width(),null,0,PcodeOp.SUBPIECE,List.of(child,constant(relative,1).origin()),List.of()));
      }
      if(whole.opcode()==PcodeOp.INT_ZEXT) {
        var child=whole.inputs().getFirst();if(offset>=child.width())return constant(0,o.width()).origin();
        if(offset+o.width()<=child.width())return canonicalOrigin(new Origin(OriginKind.OPERATION,o.width(),null,0,PcodeOp.SUBPIECE,List.of(child,constant(offset,1).origin()),List.of()));
      }
      if(whole.opcode()==PcodeOp.PIECE) {
        int low=whole.inputs().get(1).width();Origin selected=null;int relative=offset;
        if(offset+o.width()<=low)selected=whole.inputs().get(1);
        else if(offset>=low){selected=whole.inputs().get(0);relative-=low;}
        if(selected!=null)return canonicalOrigin(new Origin(OriginKind.OPERATION,o.width(),null,0,PcodeOp.SUBPIECE,List.of(selected,constant(relative,1).origin()),List.of()));
      }
    }
    if(in.size()==2&&(o.opcode()==PcodeOp.INT_AND||o.opcode()==PcodeOp.INT_OR)) {
      Origin x=in.get(0),mask=in.get(1);if(x.kind()==OriginKind.CONSTANT){var swap=x;x=mask;mask=swap;}
      if(mask.kind()==OriginKind.CONSTANT) {
        if(o.opcode()==PcodeOp.INT_AND&&mask.constant()==0)return constant(0,o.width()).origin();
        if(o.opcode()==PcodeOp.INT_OR&&mask.constant()==0)return x;
        if(o.opcode()==PcodeOp.INT_AND&&mask.constant()==truncate(-1,o.width()))return x;
        if(o.opcode()==PcodeOp.INT_AND&&x.opcode()==PcodeOp.INT_AND&&x.inputs().get(1).kind()==OriginKind.CONSTANT)
          return canonicalOrigin(new Origin(OriginKind.OPERATION,o.width(),null,0,PcodeOp.INT_AND,List.of(x.inputs().get(0),constant(mask.constant()&x.inputs().get(1).constant(),o.width()).origin()),List.of()));
        if(o.opcode()==PcodeOp.INT_AND&&x.opcode()==PcodeOp.INT_OR) {
          final Origin m=mask;var parts=x.inputs().stream().map(child->canonicalOrigin(new Origin(OriginKind.OPERATION,o.width(),null,0,PcodeOp.INT_AND,List.of(child,m),List.of()))).toList();
          return canonicalOrigin(new Origin(OriginKind.OPERATION,o.width(),null,0,PcodeOp.INT_OR,parts,List.of()));
        }
      }
    }
    if(in.size()==2&&in.get(0).equals(in.get(1))&&(o.opcode()==PcodeOp.INT_XOR||o.opcode()==PcodeOp.INT_SUB))return constant(0,o.width()).origin();
    if(o.opcode()==-1&&in.stream().allMatch(x->x.kind()==OriginKind.CONSTANT)) {
      var keys=in.stream().map(Origin::constant).toList();var rows=o.table().stream().filter(r->r.keys().equals(keys)).toList();
      if(rows.size()==1)return constant(rows.get(0).value(),o.width()).origin();
    }
    if(o.opcode()!=-1&&in.stream().allMatch(x->x.kind()==OriginKind.CONSTANT)) {
      Long value=apply(o.opcode(),o.width(),in,in.stream().map(Origin::constant).toList());if(value!=null)return constant(value,o.width()).origin();
    }
    var result=new Origin(o.kind(),o.width(),o.input(),o.constant(),o.opcode(),in,o.table());
    var bits=knownBits(result);if((bits[0]|bits[1])==truncate(-1,o.width()))return constant(bits[0],o.width()).origin();
    return result;
  }
  /** Sound bit facts used only by conditional expression normalization. */
  private static long[] knownBits(Origin o) {
    long mask=truncate(-1,o.width());
    if(o.kind()==OriginKind.CONSTANT)return new long[]{o.constant(),mask^o.constant()};
    if(o.kind()!=OriginKind.OPERATION)return new long[]{0,0};
    if(Set.of(PcodeOp.INT_EQUAL,PcodeOp.INT_NOTEQUAL,PcodeOp.INT_LESS,PcodeOp.INT_LESSEQUAL,PcodeOp.INT_SLESS,PcodeOp.INT_SLESSEQUAL,PcodeOp.INT_CARRY,PcodeOp.INT_SCARRY,PcodeOp.INT_SBORROW,PcodeOp.BOOL_NEGATE,PcodeOp.BOOL_AND,PcodeOp.BOOL_OR,PcodeOp.BOOL_XOR).contains(o.opcode()))return new long[]{0,mask&~1L};
    var a=knownBits(o.inputs().getFirst());
    if(o.opcode()==PcodeOp.INT_ZEXT)return new long[]{a[0],a[1]|(mask^truncate(-1,o.inputs().getFirst().width()))};
    if(o.inputs().size()==2) {
      var b=knownBits(o.inputs().get(1));
      if(o.opcode()==PcodeOp.INT_AND)return new long[]{a[0]&b[0],(a[1]|b[1])&mask};
      if(o.opcode()==PcodeOp.INT_OR)return new long[]{(a[0]|b[0])&mask,a[1]&b[1]};
      if(o.inputs().get(1).kind()==OriginKind.CONSTANT) {
        long count=o.inputs().get(1).constant();
        if(o.opcode()==PcodeOp.SUBPIECE){int shift=(int)count*8;return new long[]{(a[0]>>>shift)&mask,(a[1]>>>shift)&mask};}
        if(count<o.width()*8) {
          int n=(int)count;
          if(o.opcode()==PcodeOp.INT_LEFT)return new long[]{(a[0]<<n)&mask,((a[1]<<n)|((1L<<n)-1))&mask};
          if(o.opcode()==PcodeOp.INT_RIGHT)return new long[]{a[0]>>>n,(a[1]>>>n)|(mask^(mask>>>n))};
        }
      }
    }
    return new long[]{0,0};
  }
  static Value table(int width, List<Origin> inputs, List<TableRow> rows, String site) {
    if (rows.isEmpty() || rows.size() > MAX_CANDIDATES) throw new IllegalArgumentException("Abstract table condition budget exhausted");
    var values = new TreeSet<Long>(); for (var row : rows) values.add(row.value());
    return value(width, values, operation(-1, width, inputs, rows), List.of(site), "immutable byte alternatives");
  }
  /** Complete evaluation only over bounded byte input definitions and supported pure operations. */
  static Relation relation(List<Origin> origins) {
    return relation(origins, new Condition(List.of()));
  }
  static Relation relation(List<Origin> origins, Condition guard) {
    var roots = new LinkedHashSet<Origin>(); for (var t : guard.terms()) roots(t.origin(), roots); for (var o : origins) roots(o, roots);
    long cases = 1;
    for (var root : roots) {
      if (root.width() != 1 || cases > MAX_INPUT_CASES / 256) return new Relation(false, "input enumeration budget/width incomplete", 0, List.of());
      cases *= 256;
    }
    var ordered = new ArrayList<>(roots); var tuples = new TreeSet<List<Long>>((a,b) -> {
      for (int i=0;i<a.size();i++) { int c=Long.compare(a.get(i),b.get(i)); if(c!=0)return c; } return 0;
    });
    long[] work = {0};
    for (long index = 0; index < cases; index++) {
      var assignment = new HashMap<Origin,Long>(); long digits = index;
      for (var root : ordered) { assignment.put(root, digits & 255); digits >>>= 8; }
      var memo = new HashMap<Origin,Long>(); var tuple = new ArrayList<Long>();
      var allowed = matches(guard, assignment, memo, work);
      if (allowed == null) return new Relation(false, "guard evaluation unsupported or work budget exhausted", index, List.of());
      if (!allowed) continue;
      for (var origin : origins) {
        Long v = concrete(origin, assignment, memo, work);
        if (v == null) return new Relation(false, "condition evaluation unsupported or work budget exhausted", index, List.of());
        tuple.add(v);
      }
      tuples.add(List.copyOf(tuple));
      if (tuples.size() > MAX_CANDIDATES) return new Relation(false, "reachable condition budget exhausted", index, List.of());
    }
    var reachable = new ArrayList<Tuple>();
    for (var tuple : tuples) {
      var terms = new ArrayList<Term>(); for (int i=0;i<origins.size();i++) terms.add(new Term(origins.get(i),tuple.get(i)));
      reachable.add(new Tuple(tuple,new Condition(terms)));
    }
    return new Relation(true, "complete bounded structural input evaluation", cases, reachable);
  }
  static Compatibility compatible(Condition condition) {
    var relation = relation(List.of(), condition);
    if (!relation.complete()) return Compatibility.UNKNOWN;
    return relation.reachable().isEmpty() ? Compatibility.UNSAT : Compatibility.SAT;
  }
  private static Boolean matches(Condition condition, Map<Origin,Long> assignment, Map<Origin,Long> memo, long[] work) {
    for (var term : condition.terms()) {
      var value = concrete(term.origin(), assignment, memo, work);
      if (value == null) return null;
      if (value != term.value()) return false;
    }
    return true;
  }
  static boolean covers(List<Condition> conditions) {
    var roots = new LinkedHashSet<Origin>();
    for (var condition : conditions) for (var term : condition.terms()) roots(term.origin(), roots);
    long cases = 1;
    for (var root : roots) {
      if (root.width() != 1 || cases > MAX_INPUT_CASES / 256) return false;
      cases *= 256;
    }
    long[] work = {0};
    for (long index = 0; index < cases; index++) {
      long digits = index; var assignment = new HashMap<Origin,Long>();
      for (var root : roots) { assignment.put(root, digits & 255); digits >>>= 8; }
      boolean covered = false; var memo = new HashMap<Origin,Long>();
      for (var condition : conditions) {
        var matched = matches(condition, assignment, memo, work);
        if (matched == null) return false;
        if (matched) { covered = true; break; }
      }
      if (!covered) return false;
    }
    return true;
  }
  static void roots(Origin o, Set<Origin> roots) {
    if (o.kind() == OriginKind.INPUT) roots.add(o); else for (var child : o.inputs()) roots(child, roots);
  }
  static Long concrete(Origin o, Map<Origin,Long> assignment, Map<Origin,Long> memo, long[] work) {
    if (++work[0] > MAX_RELATION_WORK) return null;
    if (memo.containsKey(o)) return memo.get(o);
    Long result;
    if (o.kind() == OriginKind.INPUT) result = assignment.get(o);
    else if (o.kind() == OriginKind.CONSTANT) result = o.constant();
    else {
      var args = new ArrayList<Long>(); for (var child : o.inputs()) args.add(concrete(child,assignment,memo,work));
      if (args.stream().anyMatch(Objects::isNull)) return null;
      if (o.opcode() == -1) result = o.table().stream().filter(row -> row.keys().equals(args)).map(TableRow::value).findFirst().orElse(null);
      else result = apply(o.opcode(),o.width(),o.inputs(),args);
    }
    memo.put(o,result); return result;
  }
  /** Byte-slice storage. Unknown unique definitions are scoped to their instruction, not reused. */
  static final class Storage {
    final Map<Long,Value> registers = new HashMap<>(), uniques = new HashMap<>();
    final String scope; final boolean compactWords; String site = "entry";
    Storage(String scope) { this(scope,false); }
    Storage(String scope,boolean compactWords) { this.scope = scope;this.compactWords=compactWords; }
    void instruction(String at) { site=at; uniques.clear(); }
    Value get(Varnode node) {
      if (node.isConstant()) return constant(node.getOffset(),node.getSize());
      var storage = node.isRegister()?registers:node.isUnique()?uniques:null;
      String slice=node.isRegister()?"entry-register-byte":"undefined-unique-byte:"+site;
      if (storage==null) return input(scope, "unsupported-storage:"+node.getAddress().getAddressSpace().getName(),node.getOffset(),node.getSize());
      var octets=new ArrayList<Value>();
      for(int b=0;b<node.getSize();b++) octets.add(storage.getOrDefault(node.getOffset()+b,input(scope,slice,node.getOffset()+b,1)));
      // Reassemble slices of one unchanged word without duplicating its provenance tree.
      if(compactWords&&octets.size()>1) {
        var first=octets.getFirst().origin();
        if(first.kind()==OriginKind.OPERATION&&first.opcode()==PcodeOp.SUBPIECE&&first.inputs().size()==2) {
          var whole=first.inputs().getFirst();boolean intact=whole.width()==node.getSize();
          for(int b=0;b<octets.size()&&intact;b++) {
            var part=octets.get(b).origin();
            intact=part.kind()==OriginKind.OPERATION&&part.opcode()==PcodeOp.SUBPIECE&&part.inputs().size()==2
                &&part.inputs().getFirst().equals(whole)&&part.inputs().get(1).kind()==OriginKind.CONSTANT&&part.inputs().get(1).constant()==b;
          }
          if(intact) {
            TreeSet<Long> cover=new TreeSet<>(List.of(0L));
            for(int b=0;b<octets.size()&&cover!=null;b++) {
              if(octets.get(b).values()==null){cover=null;break;}
              var next=new TreeSet<Long>();
              for(long prefix:cover)for(long octet:octets.get(b).values())next.add(prefix|(octet<<(8*b)));
              cover=next.size()>MAX_VALUES?null:next;
            }
            return value(node.getSize(),cover,whole,sites(octets,site),"reassembled unchanged storage slices");
          }
        }
      }
      Value combined=octets.get(octets.size()-1);
      for(int b=octets.size()-2;b>=0;b--) combined=evaluate(PcodeOp.PIECE,combined.width()+1,List.of(combined,octets.get(b)),site);
      return combined;
    }
    void put(Varnode node,Value value) {
      var storage=node.isRegister()?registers:node.isUnique()?uniques:null;if(storage==null)return;
      for(int b=0;b<node.getSize();b++) storage.put(node.getOffset()+b,node.getSize()==1?value:
          evaluate(PcodeOp.SUBPIECE,1,List.of(value,constant(b,4)),site));
    }
  }
}
