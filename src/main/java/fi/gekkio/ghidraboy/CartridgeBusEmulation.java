package fi.gekkio.ghidraboy;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.pcode.emulate.Emulate;
import ghidra.pcode.emulate.EmulateInstructionStateModifier;
import ghidra.pcode.memstate.MemoryState;
import ghidra.pcode.memstate.MemoryBank;
import ghidra.pcode.memstate.MemoryPageOverlay;
import ghidra.program.model.pcode.Varnode;
import java.lang.ref.WeakReference;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.WeakHashMap;

/** Preserves the existing flat CPU emulator; explicit contexts add bounded direct cartridge writes. */
public final class CartridgeBusEmulation extends EmulateInstructionStateModifier {
  public static final int DEFAULT_DIAGNOSTIC_CAPACITY = 4096;
  private static final Map<MemoryState, WeakReference<Context>> CONTEXTS =
      Collections.synchronizedMap(new WeakHashMap<>());

  public record Write(int address, int value) {}

  public static final class Context implements AutoCloseable {
    private final WeakReference<MemoryState> memory;
    private final Cartridge cartridge;
    private final int diagnosticCapacity;
    private final ArrayDeque<Write> writes = new ArrayDeque<>();
    private final MemoryBank originalBank;
    private final GuardBank guardBank;
    private MapperState state;
    private long droppedWrites;
    private long rejectedControlWrites;

    private Context(
        MemoryState memory, Cartridge cartridge, MapperState state, int diagnosticCapacity, MemoryBank bank) {
      this.memory = new WeakReference<>(memory);
      this.cartridge = cartridge;
      this.state = Objects.requireNonNull(state, "Explicit initial mapper state is required");
      this.diagnosticCapacity = diagnosticCapacity;
      this.originalBank = bank;
      this.guardBank = new GuardBank(bank, this);
    }

    public MapperState state() {
      return state;
    }

    /** Most recent retained writes in execution order. Truncation never changes execution. */
    public List<Write> writes() {
      return List.copyOf(writes);
    }

    public long droppedWrites() {
      return droppedWrites;
    }

    public long rejectedControlWrites() {
      return rejectedControlWrites;
    }

    private void record(int address, int value) {
      if (writes.size() == diagnosticCapacity) {
        writes.removeFirst();
        droppedWrites++;
      }
      writes.addLast(new Write(address, value));
    }

    @Override
    public void close() {
      var currentMemory = memory.get();
      if (currentMemory == null) return;
      synchronized (CONTEXTS) {
        if (context(currentMemory) != this) return;
        CONTEXTS.remove(currentMemory);
        if (currentMemory.getMemoryBank(originalBank.getSpace()) == guardBank)
          currentMemory.setMemoryBank(originalBank);
      }
    }
  }

  private static Context context(MemoryState memory) {
    var reference = CONTEXTS.get(memory);
    return reference == null ? null : reference.get();
  }

  /** A write-through bank guard; reads and ordinary writes retain the original memory backing. */
  private static final class GuardBank extends MemoryPageOverlay {
    private final Context context;

    GuardBank(MemoryBank original, Context context) {
      super(original.getSpace(), original, original.getMemoryFaultHandler());
      this.context = context;
    }

    @Override
    public void setChunk(long offset, int size, byte[] values) {
      // Validate the whole operation before committing any byte, including a 16-bit wrap.
      for (int i = 0; i < size; i++) {
        int cpu = (int) ((offset + i) & 0xffff);
        if (cpu < 0x8000) {
          context.rejectedControlWrites++;
          throw new IllegalStateException(
              String.format(
                  "Unsupported cartridge-control STORE at %04x; bounded context requires direct write hooks",
                  cpu));
        }
      }
      underlie.setChunk(offset, size, values);
    }

    @Override
    public int getChunk(long offset, int size, byte[] values, boolean stopOnUninitialized) {
      return underlie.getChunk(offset, size, values, stopOnUninitialized);
    }

    @Override
    public void setInitialized(long offset, int size, boolean initialized) {
      underlie.setInitialized(offset, size, initialized);
    }
  }

  public static Context attach(EmulatorHelper helper, MapperState state) {
    return attach(helper, state, DEFAULT_DIAGNOSTIC_CAPACITY);
  }

  public static Context attach(EmulatorHelper helper, MapperState state, int diagnosticCapacity) {
    if (diagnosticCapacity <= 0)
      throw new IllegalArgumentException("Diagnostic capacity must be positive");
    var cartridge = ProgramMapping.cartridge(helper.getProgram());
    if (!CartridgeBus.supportsControls(cartridge))
      throw new IllegalArgumentException("An established supported cartridge descriptor is required");
    var memory = helper.getEmulator().getMemState();
    synchronized (CONTEXTS) {
      if (context(memory) != null) throw new IllegalStateException("Bus context already attached");
      var bank = memory.getMemoryBank(helper.getLanguage().getAddressFactory().getDefaultAddressSpace());
      if (bank == null) throw new IllegalArgumentException("Flat CPU memory bank is required");
      var context = new Context(memory, cartridge, state, diagnosticCapacity, bank);
      memory.setMemoryBank(context.guardBank);
      CONTEXTS.put(memory, new WeakReference<>(context));
      return context;
    }
  }

  public CartridgeBusEmulation(Emulate emulator) {
    super(emulator);
    registerPcodeOpBehavior(CartridgeBus.DIRECT_WRITE8, (e, o, i) -> write(e, o, i, 1, false));
    registerPcodeOpBehavior(CartridgeBus.DIRECT_WRITE16, (e, o, i) -> write(e, o, i, 2, false));
    registerPcodeOpBehavior(CartridgeBus.CARTRIDGE_WRITE8, (e, o, i) -> write(e, o, i, 1, true));
  }

  private static void write(
      Emulate emulator, Varnode output, Varnode[] inputs, int width, boolean requiresCartridge) {
    if (output != null
        || inputs.length != 2
        || inputs[0].getSize() != 2
        || inputs[1].getSize() != width)
      throw new IllegalArgumentException("Invalid direct bus write operands");
    var memory = emulator.getMemoryState();
    int cpu = (int) (memory.getValue(inputs[0]) & 0xffff);
    int value = (int) (memory.getValue(inputs[1]) & 0xffff);
    for (int i = 0; i < width; i++)
      writeByte(emulator, (cpu + i) & 0xffff, (value >>> (8 * i)) & 255, requiresCartridge);
  }

  private static void writeByte(Emulate emulator, int cpu, int value, boolean requiresCartridge) {
    var memory = emulator.getMemoryState();
    var context = context(memory);
    if (requiresCartridge && context == null)
      throw new IllegalStateException("Cartridge bus state is required");
    if (context != null) {
      context.record(cpu, value);
      context.state = context.state.write(context.cartridge, cpu, value);
      if (cpu < 0x8000) return;
    }
    // Default EmulatorHelper remains its documented flat, writable 64 KiB CPU model.
    memory.setValue(
        emulator.getLanguage().getAddressFactory().getDefaultAddressSpace(), cpu, 1, value);
  }
}
