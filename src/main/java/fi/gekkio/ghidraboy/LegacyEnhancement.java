package fi.gekkio.ghidraboy;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/** Explicit metadata-only reconstruction: never changes an annotated program's topology. */
public final class LegacyEnhancement {
  private LegacyEnhancement() {}

  public static ProgramMapping.Snapshot enhance(
      Program p, String mapperOverride, TaskMonitor monitor) throws Exception {
    return enhance(p, mapperOverride, null, monitor);
  }

  public static ProgramMapping.Snapshot enhance(
      Program p, String mapperOverride, GameBoyKind hardware, TaskMonitor monitor)
      throws Exception {
    if (!p.getLanguageID().toString().equals("SM83:LE:16:default"))
      throw new IllegalArgumentException("Not an SM83 program");
    var existing = ProgramMapping.cartridge(p);
    if (existing != null) {
      if (hardware != null) {
        int id = p.startTransaction("Explicit legacy hardware identification");
        boolean done = false;
        try {
          p.getOptions(ProgramMapping.OPTIONS)
              .setString("cartridge", ProgramMapping.JSON.toJson(existing.withHardware(hardware)));
          p.getOptions(ProgramMapping.OPTIONS).setString("hardware", hardware.name());
          p.getOptions(ProgramMapping.OPTIONS)
              .setString("hardwareProvenance", "explicit enhancement choice");
          monitor.checkCancelled();
          done = true;
        } finally {
          p.endTransaction(id, done);
        }
      }
      return ProgramMapping.inspect(p);
    }
    var source = ProgramMapping.originalFile(p);
    byte[] bytes = new byte[Math.toIntExact(source.getSize())];
    source.getOriginalBytes(0, bytes);
    String historical = p.getOptions(ProgramMapping.OPTIONS).getString("hardware", "UNKNOWN");
    if (!historical.equals("GB") && !historical.equals("CGB")) historical = "UNKNOWN";
    var descriptor =
        Cartridge.parse(bytes, mapperOverride)
            .withHardwareChoice(hardware == null ? historical : hardware.name());
    monitor.checkCancelled();
    int tx = p.startTransaction("Explicit GhidraBoy metadata enhancement");
    boolean success = false;
    try {
      var opts = p.getOptions(ProgramMapping.OPTIONS);
      opts.setInt("schemaVersion", ProgramMapping.SCHEMA_VERSION);
      opts.setString("cartridge", ProgramMapping.JSON.toJson(descriptor));
      opts.setString("inputMode", "CARTRIDGE");
      opts.setString("hardware", descriptor.hardware());
      opts.setString(
          "hardwareProvenance",
          hardware != null
              ? "explicit enhancement choice"
              : descriptor.hardwareKnown()
                  ? "persisted historical choice"
                  : "not recovered; header not authoritative");
      opts.setString(
          "mappingProvenance",
          "Explicit legacy reconstruction from original FileBytes; RAM remains unresolved without"
              + " anchors");
      opts.setString("mapperOverride", mapperOverride);
      monitor.checkCancelled();
      success = true;
    } finally {
      p.endTransaction(tx, success);
    }
    return ProgramMapping.inspect(p);
  }
}
