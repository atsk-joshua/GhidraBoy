package fi.gekkio.ghidraboy;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockType;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/** Conservative, transaction-ready recognition of the historical GhidraBoy Program topology. */
public final class LegacyPreparation {
  public static final int VERSION = 1;

  public record Candidate(
      String region,
      int bank,
      String address,
      long length,
      String evidence,
      boolean alreadyIdentified) {}

  public record Plan(
      int version,
      long programModification,
      Cartridge cartridge,
      boolean descriptorChange,
      List<Candidate> candidates,
      List<String> devices,
      List<String> diagnostics,
      int mutationCount) {
    public Plan {
      candidates = List.copyOf(candidates);
      devices = List.copyOf(devices);
      diagnostics = List.copyOf(diagnostics);
    }

    public boolean ready() {
      return diagnostics.isEmpty();
    }
  }

  private record HistoricalBlock(
      String name,
      String space,
      long start,
      long length,
      String region,
      int bank,
      boolean execute) {}

  private LegacyPreparation() {}

  public static Plan preview(Program program, TaskMonitor monitor) throws Exception {
    if (!program.getLanguageID().toString().equals("SM83:LE:16:default"))
      throw new IllegalArgumentException("Not an SM83 Program");

    var original = ProgramMapping.originalFile(program);
    byte[] bytes = new byte[Math.toIntExact(original.getSize())];
    original.getOriginalBytes(0, bytes);
    var reconstructed = Cartridge.parse(bytes, "AUTO");
    String historicalHardware =
        program.getOptions(ProgramMapping.OPTIONS).contains("hardware")
            ? program.getOptions(ProgramMapping.OPTIONS).getString("hardware", "UNKNOWN")
            : "UNKNOWN";
    String hardware = hardwareChoice(reconstructed, historicalHardware);
    reconstructed = reconstructed.withHardwareChoice(hardware);

    var existing = ProgramMapping.cartridge(program);
    if (existing != null
        && (!existing.inputSha256().equals(reconstructed.inputSha256())
            || existing.inputLength() != reconstructed.inputLength()))
      throw new IllegalArgumentException(
          "Existing cartridge descriptor conflicts with immutable FileBytes");
    var cartridge = existing == null ? reconstructed : existing;
    if (!cartridge.hardwareKnown() && !hardware.equals("UNKNOWN"))
      cartridge = cartridge.withHardwareChoice(hardware);
    boolean descriptorChange =
        existing == null
            || !ProgramMapping.JSON.toJson(existing).equals(ProgramMapping.JSON.toJson(cartridge));

    var diagnostics = new ArrayList<String>();
    validateHistoricalRom(program, cartridge, diagnostics, monitor);

    var specifications = new ArrayList<HistoricalBlock>();
    specifications.add(new HistoricalBlock("xram", "ram", 0xa000, 0x2000, "SRAM", 0, true));
    specifications.add(new HistoricalBlock("wram0", "ram", 0xc000, 0x1000, "WRAM", 0, true));
    specifications.add(new HistoricalBlock("hram", "ram", 0xff80, 0x7f, "HRAM", 0, true));
    if (cartridge.color()) {
      specifications.add(
          new HistoricalBlock("vram0", "vram0", 0x8000, 0x2000, "VRAM", 0, false));
      specifications.add(
          new HistoricalBlock("vram1", "vram1", 0x8000, 0x2000, "VRAM", 1, false));
      for (int bank = 1; bank <= 7; bank++)
        specifications.add(
            new HistoricalBlock(
                "wram" + bank, "wram" + bank, 0xd000, 0x1000, "WRAM", bank, true));
    }

    var candidates = new ArrayList<Candidate>();
    var identities = new ArrayList<ProgramMapping.RamIdentity>();
    for (var specification : specifications) {
      monitor.checkCancelled();
      if (specification.region().equals("SRAM") && cartridge.ramBytes() == 0) continue;
      var space = program.getAddressFactory().getAddressSpace(specification.space());
      if (space == null) continue;
      Address start = space.getAddressInThisSpaceOnly(specification.start());
      MemoryBlock block = program.getMemory().getBlock(start);
      if (block == null) continue;
      String problem = validateHistoricalBlock(program, block, specification);
      if (problem != null) {
        diagnostics.add(
            "Ambiguous historical "
                + specification.region()
                + specification.bank()
                + " candidate at "
                + start
                + ": "
                + problem);
        continue;
      }
      var identity =
          new ProgramMapping.RamIdentity(
              start,
              specification.length(),
              specification.region(),
              specification.bank(),
              0);
      identities.add(identity);
      boolean identified =
          ProgramMapping.staticToPhysical(program, start).stream()
              .anyMatch(
                  physical ->
                      physical.region().equals(specification.region())
                          && physical.bank() == specification.bank()
                          && physical.offset() == 0);
      candidates.add(
          new Candidate(
              specification.region(),
              specification.bank(),
              start.toString(),
              specification.length(),
              "coherent historical GhidraBoy family; exact space/range/permissions/provenance",
              identified));
    }

    var devices = new ArrayList<String>();
    classifyDevice(program, "oam", 0xfe00, 0xa0, devices, diagnostics);
    classifyDevice(program, "io", 0xff00, 0x80, devices, diagnostics);
    classifyDevice(program, "ie", 0xffff, 1, devices, diagnostics);

    try {
      ProgramMapping.preflightRamIdentities(program, identities, monitor);
    } catch (IllegalArgumentException conflict) {
      diagnostics.add(conflict.getMessage());
    }
    candidates.sort(
        Comparator.comparing(Candidate::region)
            .thenComparingInt(Candidate::bank)
            .thenComparing(Candidate::address));
    int mutations =
        (descriptorChange ? 1 : 0)
            + (int) candidates.stream().filter(candidate -> !candidate.alreadyIdentified()).count();
    var options = program.getOptions(ProgramMapping.OPTIONS);
    boolean markerCurrent =
        options.contains("legacyPreparationVersion")
            && options.getInt("legacyPreparationVersion", 0) == VERSION;
    if (!markerCurrent && mutations == 0 && diagnostics.isEmpty()) mutations++;
    return new Plan(
        VERSION,
        program.getModificationNumber(),
        cartridge,
        descriptorChange,
        candidates,
        devices,
        diagnostics,
        mutations);
  }

  public static Plan prepare(Program program, TaskMonitor monitor) throws Exception {
    var plan = preview(program, monitor);
    if (!plan.ready())
      throw new IllegalArgumentException(
          "Legacy preparation refused before mutation: " + String.join("; ", plan.diagnostics()));
    if (plan.mutationCount() == 0) return plan;
    if (program.getModificationNumber() != plan.programModification())
      throw new IllegalStateException("Program changed after legacy preparation preflight");

    var identities = new ArrayList<ProgramMapping.RamIdentity>();
    for (var candidate : plan.candidates())
      if (!candidate.alreadyIdentified())
        identities.add(
            new ProgramMapping.RamIdentity(
                ProgramMapping.staticAddress(program, candidate.address()),
                candidate.length(),
                candidate.region(),
                candidate.bank(),
                0));
    ProgramMapping.preflightRamIdentities(program, identities, monitor);

    int transaction = program.startTransaction("Prepare historical GhidraBoy Program");
    boolean commit = false;
    try {
      monitor.checkCancelled();
      var options = program.getOptions(ProgramMapping.OPTIONS);
      if (plan.descriptorChange()) {
        options.setInt("schemaVersion", ProgramMapping.SCHEMA_VERSION);
        options.setString("cartridge", ProgramMapping.JSON.toJson(plan.cartridge()));
        options.setString("inputMode", "CARTRIDGE");
        options.setString("hardware", plan.cartridge().hardware());
        options.setString("hardwareProvenance", hardwareProvenance(plan.cartridge()));
        options.setString("mappingProvenance", "Conservative structural recognition of historical GhidraBoy topology");
        options.setString("mapperOverride", "AUTO");
      }
      ProgramMapping.applyRamIdentities(program, identities, "legacy-structural-recognition", monitor);
      options.setInt("legacyPreparationVersion", VERSION);
      options.setString("legacyPreparationState", "PREPARED");
      monitor.checkCancelled();
      commit = true;
    } finally {
      program.endTransaction(transaction, commit);
    }
    var result = preview(program, monitor);
    if (!result.ready() || result.mutationCount() != 0)
      throw new IllegalStateException("Legacy preparation postcondition is not idempotent");
    return result;
  }

  private static String hardwareChoice(Cartridge cartridge, String historical) {
    if (Objects.equals(historical, "GB") || Objects.equals(historical, "CGB")) return historical;
    if (cartridge.cgb() == 0xc0) return "CGB";
    if ((cartridge.cgb() & 0x80) == 0) return "GB";
    return "UNKNOWN";
  }

  private static String hardwareProvenance(Cartridge cartridge) {
    if (cartridge.cgb() == 0xc0) return "CGB-only cartridge header";
    if ((cartridge.cgb() & 0x80) == 0) return "DMG cartridge header";
    return "persisted historical choice or unresolved CGB-compatible hardware";
  }

  private static void validateHistoricalRom(
      Program program,
      Cartridge cartridge,
      List<String> diagnostics,
      TaskMonitor monitor)
      throws Exception {
    var snapshot = ProgramMapping.inspect(program);
    var ranges =
        snapshot.ranges().stream()
            .filter(range -> range.region().equals("ROM"))
            .sorted(Comparator.comparingInt(ProgramMapping.Range::bank))
            .toList();
    if (ranges.size() != cartridge.actualRomBanks()) {
      diagnostics.add(
          "Historical ROM family is incomplete: expected "
              + cartridge.actualRomBanks()
              + " banks, found "
              + ranges.size());
      return;
    }
    for (int bank = 0; bank < ranges.size(); bank++) {
      monitor.checkCancelled();
      var range = ranges.get(bank);
      String expectedSpace = bank == 0 ? program.getAddressFactory().getDefaultAddressSpace().getName() : "rom" + bank;
      long expectedStart = bank == 0 ? 0 : 0x4000;
      if (range.bank() != bank
          || range.offset() != 0
          || range.length() != 0x4000
          || !range.space().equals(expectedSpace)
          || range.start() != expectedStart
          || range.fileOffset() == null
          || range.fileOffset() != bank * 0x4000L
          || !range.read()
          || range.write()
          || !range.execute())
        diagnostics.add("ROM bank " + bank + " is not the coherent historical GhidraBoy layout");
    }
  }

  private static String validateHistoricalBlock(
      Program program, MemoryBlock block, HistoricalBlock expected) {
    if (!block.getName().equals(expected.name())) return "unexpected block name " + block.getName();
    if (!block.getStart().getAddressSpace().getName().equals(expected.space())) return "wrong address space";
    if (block.getStart().getOffset() != expected.start() || block.getSize() != expected.length())
      return "wrong bounds";
    if (block.getType() != MemoryBlockType.DEFAULT) return "mapped/bit-mapped storage is not canonical RAM";
    if (block.isInitialized()) return "initialized storage is not historical uninitialized RAM";
    if (!block.isRead() || !block.isWrite() || block.isExecute() != expected.execute())
      return "permissions differ from the historical loader contract";
    if (block.isVolatile()) return "volatile storage is not ordinary RAM";
    if (block.getSourceInfos().stream()
        .anyMatch(info -> info.getFileBytes().isPresent() || info.getMappedRange().isPresent()))
      return "file or alias provenance is not ordinary RAM";
    return null;
  }

  private static void classifyDevice(
      Program program,
      String expectedName,
      long offset,
      long length,
      List<String> devices,
      List<String> diagnostics) {
    var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    var block = program.getMemory().getBlock(start);
    if (block == null) return;
    if (!block.getName().equals(expectedName)
        || block.getStart().getOffset() != offset
        || block.getSize() != length
        || block.getType() != MemoryBlockType.DEFAULT
        || block.isInitialized()
        || !block.isRead()
        || !block.isWrite()
        || block.isExecute()) {
      diagnostics.add("Ambiguous historical device candidate at " + start);
      return;
    }
    devices.add(expectedName.toUpperCase() + " " + start + " remains a device/unresolved region");
  }
}
