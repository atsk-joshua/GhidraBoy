package fi.gekkio.ghidraboy;

import ghidra.app.util.PseudoDisassembler;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.util.*;

/**
 * Read-only decoding at roots requested by the software-call proof. This class never follows
 * decoded flow: the caller must justify each next physical fetch using its architectural state.
 * A failed proof can discard its session without having changed any Program knowledge.
 */
public final class SoftwareCallInstructionDiscovery {
  private SoftwareCallInstructionDiscovery() {}
  public static final String VERSION = "software-call-rooted-discovery-1";
  private static final ThreadLocal<Session> ACTIVE = new ThreadLocal<>();

  public record Candidate(String address, int length, String bytes,
      List<MapperState.Physical> physicalBytes, String reason, String mnemonic, List<String> comments) {
    public Candidate { physicalBytes = List.copyOf(physicalBytes); comments = List.copyOf(comments); }
  }

  public record Reservation(String address, int length, String reason) {}

  public record Plan(String version, String dependencies, List<Candidate> candidates,
      List<Reservation> reservations) {
    public Plan { candidates = List.copyOf(candidates); reservations = List.copyOf(reservations); }

    /** Revalidates both consumed bytes and all annotation/context/mapping dependencies. */
    public void requireCurrent(Program program, TaskMonitor monitor) throws Exception {
      if (!VERSION.equals(version) || !dependencies.equals(FarCallEvidence.capture(program, monitor)))
        throw new IllegalArgumentException("Stale or incompatible rooted instruction discovery plan");
      try (var session = begin(program, monitor)) {
        for (var reservation : reservations)
          session.reserve(ProgramMapping.staticAddress(program, reservation.address), reservation.length, reservation.reason);
        for (var candidate : candidates) {
          var at = ProgramMapping.staticAddress(program, candidate.address);
          if (program.getListing().getInstructionAt(at) != null)
            throw new IllegalArgumentException("Discovery boundary was already committed at " + at);
          instructionAt(program, at, candidate.reason, monitor);
        }
        if (!ProgramMapping.JSON.toJsonTree(this).equals(ProgramMapping.JSON.toJsonTree(session.plan(monitor))))
          throw new IllegalArgumentException("Rooted discovery inventory changed");
      }
    }
  }

  public static final class Session implements AutoCloseable {
    private final Program program;
    private final Session previous;
    private final String dependencies;
    private final long modification;
    private final Map<Address, Instruction> decoded = new LinkedHashMap<>();
    private final Map<Address, Candidate> candidates = new LinkedHashMap<>();
    private final List<Reservation> reservations = new ArrayList<>();
    private final AddressSet reserved = new AddressSet();
    private boolean closed;

    private Session(Program program, TaskMonitor monitor) throws Exception {
      this.program = Objects.requireNonNull(program);
      modification = program.getModificationNumber();
      dependencies = FarCallEvidence.capture(program, monitor);
      previous = ACTIVE.get();
      ACTIVE.set(this);
    }

    /** Reserve convention-proven payload/data before requesting any potentially overlapping code. */
    public void reserve(Address start, int length, String reason) throws Exception {
      requireActive();
      if (length < 1 || reason == null || reason.isBlank()) throw new IllegalArgumentException("Invalid discovery reservation");
      var end = start.addNoWrap(length - 1L);
      for (var instruction : decoded.values())
        if (new AddressSet(start, end).intersects(new AddressSet(instruction.getAddress(), instruction.getMaxAddress())))
          throw new IllegalArgumentException("Discovery root overlaps reserved " + reason + " at " + start);
      var reservation = new Reservation(start.toString(), length, reason);
      if (!reservations.contains(reservation)) reservations.add(reservation);
      reserved.add(start, end);
    }

    public Plan plan(TaskMonitor monitor) throws Exception {
      requireActive();
      monitor.checkCancelled();
      if (modification != program.getModificationNumber()
          || !dependencies.equals(FarCallEvidence.capture(program, monitor)))
        throw new IllegalStateException("Program changed during rooted instruction discovery");
      return new Plan(VERSION, dependencies, List.copyOf(candidates.values()), reservations);
    }

    private void requireActive() {
      if (closed || ACTIVE.get() != this) throw new IllegalStateException("Inactive rooted discovery session");
    }

    @Override public void close() {
      requireActive();
      closed = true;
      if (previous == null) ACTIVE.remove(); else ACTIVE.set(previous);
    }
  }

  public static Session begin(Program program, TaskMonitor monitor) throws Exception {
    return new Session(program, monitor);
  }

  /** A read-only alternative's inventory boundary; never a Program transaction or decode authority. */
  public static final class Checkpoint {
    private final Session session;
    private final Map<Address, Instruction> decoded;
    private final Map<Address, Candidate> candidates;
    private final List<Reservation> reservations;
    private final AddressSet reserved;
    private Checkpoint(Session session) {
      this.session = session;
      decoded = new LinkedHashMap<>(session.decoded);
      candidates = new LinkedHashMap<>(session.candidates);
      reservations = List.copyOf(session.reservations);
      reserved = new AddressSet(session.reserved);
    }
  }

  public static Checkpoint checkpoint(Program program) {
    var session = ACTIVE.get();
    if (session == null || session.program != program)
      throw new IllegalStateException("No matching rooted discovery session");
    session.requireActive();
    return new Checkpoint(session);
  }

  /** Discard every candidate from an abandoned proof alternative before evaluating its fallback. */
  public static void rollback(Program program, Checkpoint checkpoint) {
    var session = ACTIVE.get();
    if (session == null || session.program != program || checkpoint.session != session)
      throw new IllegalStateException("Discovery checkpoint belongs to another scope");
    session.requireActive();
    session.decoded.clear(); session.decoded.putAll(checkpoint.decoded);
    session.candidates.clear(); session.candidates.putAll(checkpoint.candidates);
    session.reservations.clear(); session.reservations.addAll(checkpoint.reservations);
    session.reserved.clear(); session.reserved.add(checkpoint.reserved);
  }

  /** Listing lookup outside a session; isolated speculative decoding inside a review session. */
  public static Instruction instructionAt(Program program, Address address, String reason,
      TaskMonitor monitor) throws Exception {
    monitor.checkCancelled();
    var session = ACTIVE.get();
    if (session != null && session.program != program)
      throw new IllegalArgumentException("Rooted discovery session belongs to another Program");
    if (session != null && session.reserved.contains(address))
      throw new IllegalArgumentException("Instruction root lies in reserved payload/data at " + address);
    var existing = program.getListing().getInstructionAt(address);
    if (existing != null || session == null) return existing;
    session.requireActive();
    if (reason == null || reason.isBlank()) throw new IllegalArgumentException("Discovery requires a justified root");
    if (session.decoded.containsKey(address)) return session.decoded.get(address);
    var instruction = new PseudoDisassembler(program).disassemble(address);
    if (instruction == null || instruction.getLength() < 1)
      throw new IllegalArgumentException("Root cannot be decoded at " + address);
    var physical = new ArrayList<MapperState.Physical>();
    var comments = new ArrayList<String>();
    var rootFunction = program.getFunctionManager().getFunctionContaining(address);
    for (int offset = 0; offset < instruction.getLength(); offset++) {
      monitor.checkCancelled();
      var at = address.addNoWrap(offset);
      if (session.reserved.contains(at)) throw new IllegalArgumentException("Instruction overlaps reserved payload/data at " + at);
      var identities = ProgramMapping.staticToPhysical(program, at);
      var block = program.getMemory().getBlock(at);
      if (identities.size() != 1 || !identities.get(0).region().equals("ROM") || block == null
          || !block.isInitialized() || !block.isExecute() || block.isWrite() || block.isVolatile())
        throw new IllegalArgumentException("Discovery requires immutable executable physical ROM at " + at);
      physical.add(identities.get(0));
      for (var type : ghidra.program.model.listing.CommentType.values())
        comments.add(offset + ":" + type + ":" + program.getListing().getComment(type, at));
      if (program.getListing().getInstructionContaining(at) != null || program.getListing().getDefinedDataContaining(at) != null)
        throw new IllegalArgumentException("Discovery conflicts with existing code/data boundary at " + at);
      for (var other : session.decoded.values())
        if (other.contains(at)) throw new IllegalArgumentException("Conflicting speculative instruction boundary at " + at);
      if (!Objects.equals(rootFunction, program.getFunctionManager().getFunctionContaining(at)))
        throw new IllegalArgumentException("Discovery crosses an existing function boundary at " + at);
      if (offset != 0) {
        for (var symbol : program.getSymbolTable().getSymbols(at))
          if (!symbol.isDynamic()) throw new IllegalArgumentException("Discovery crosses a named boundary at " + at);
        if (program.getReferenceManager().getReferencesTo(at).hasNext()
            || program.getReferenceManager().getReferencesFrom(at).length != 0)
          throw new IllegalArgumentException("Discovery crosses a referenced boundary at " + at);
      }
    }
    // Existing endpoint/override references must agree even though there is no listing Instruction.
    // Fixup/contracts remain the effect engine's obligation: a declared nested software call may
    // legitimately target an installed helper, but discovering its bytes does not prove its effects.
    var defaultFlows = Arrays.asList(instruction.getDefaultFlows());
    for (var reference : program.getReferenceManager().getReferencesFrom(address))
      if (InstructionInterpretation.relevant(reference)
          && (reference.getReferenceType().isOverride() || !defaultFlows.contains(reference.getToAddress())
              || !reference.getReferenceType().equals(instruction.getFlowType())))
        throw new IllegalArgumentException("Discovery root has conflicting flow annotation at " + address);
    byte[] bytes = new byte[instruction.getLength()];
    program.getMemory().getBytes(address, bytes);
    session.decoded.put(address, instruction);
    session.candidates.put(address, new Candidate(address.toString(), instruction.getLength(),
        HexFormat.of().formatHex(bytes), physical, reason, instruction.getMnemonicString(), comments));
    return instruction;
  }

  /**
   * Commits only reviewed instruction extents, without following their outgoing flows. Enclosing
   * application transactions may roll these changes back together with contracts and ownership.
   */
  public static void apply(Program program, Plan plan, TaskMonitor monitor) throws Exception {
    plan.requireCurrent(program, monitor);
    int transaction = program.startTransaction("Apply reviewed rooted instruction discovery");
    boolean success = false;
    try {
      plan.requireCurrent(program, monitor);
      var messages = new ArrayList<String>();
      var disassembler = Disassembler.getDisassembler(program, monitor, messages::add);
      for (var candidate : plan.candidates) {
        monitor.checkCancelled();
        var start = ProgramMapping.staticAddress(program, candidate.address);
        var originalReferences = referenceInventory(program, start);
        var originalSymbols = symbolInventory(program, start);
        var extent = new AddressSet(start, start.addNoWrap(candidate.length - 1L));
        var actual = disassembler.disassemble(start, extent, false);
        var instruction = program.getListing().getInstructionAt(start);
        if (!messages.isEmpty() || instruction == null || instruction.getLength() != candidate.length
            || !actual.equals(extent)
            || !HexFormat.of().formatHex(instruction.getBytes()).equals(candidate.bytes)
            || !instruction.getMnemonicString().equals(candidate.mnemonic))
          throw new IllegalArgumentException("Reviewed decode did not commit exactly at " + start + ": " + messages);
        if (!referenceInventory(program, start).containsAll(originalReferences)
            || !symbolInventory(program, start).containsAll(originalSymbols))
          throw new IllegalArgumentException("Rooted instruction commit changed existing references or labels at " + start);
        for (int offset = 0, comment = 0; offset < candidate.length; offset++)
          for (var type : ghidra.program.model.listing.CommentType.values())
            if (!candidate.comments.get(comment++).equals(offset + ":" + type + ":"
                + program.getListing().getComment(type, start.add(offset))))
              throw new IllegalArgumentException("Rooted instruction commit changed existing comments at " + start);
      }
      monitor.checkCancelled();
      success = true;
    } finally {
      program.endTransaction(transaction, success);
    }
  }

  private static Set<String> referenceInventory(Program program, Address address) {
    var inventory = new HashSet<String>();
    for (var reference : program.getReferenceManager().getReferencesFrom(address))
      inventory.add(reference.getToAddress() + ":" + reference.getReferenceType() + ":"
          + reference.getOperandIndex() + ":" + reference.getSource() + ":"
          + reference.isPrimary() + ":" + reference.getSymbolID());
    return inventory;
  }

  private static Set<String> symbolInventory(Program program, Address address) {
    var inventory = new HashSet<String>();
    for (var symbol : program.getSymbolTable().getSymbols(address))
      if (!symbol.isDynamic()) inventory.add(symbol.getID() + ":" + symbol.getName(true)
          + ":" + symbol.getSource() + ":" + symbol.isPrimary() + ":" + symbol.isPinned());
    return inventory;
  }
}
