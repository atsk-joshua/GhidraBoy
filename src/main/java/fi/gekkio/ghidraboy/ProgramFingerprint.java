package fi.gekkio.ghidraboy;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/** Canonically ordered dependencies survive save/reopen and retain meaningful invalidation. */
public final class ProgramFingerprint {
  private ProgramFingerprint() {}

  private static String address(Address address) {
    return address == null
        ? "none"
        : address.getAddressSpace().getName()
            + ":"
            + Long.toUnsignedString(address.getOffset(), 16);
  }

  public static Map<String, String> components(Program p, TaskMonitor monitor) throws Exception {
    var parts = new TreeMap<String, String>();
    parts.put(
        "mapping",
        Sha256.of(
                ProgramMapping.JSON
                    .toJson(ProgramMapping.inspect(p))
                    .getBytes(StandardCharsets.UTF_8))
            .toString());
    var memory = MessageDigest.getInstance("SHA-256");
    byte[] buffer = new byte[16384];
    var blocks = new ArrayList<>(Arrays.asList(p.getMemory().getBlocks()));
    blocks.sort(Comparator.comparing(block -> address(block.getStart())));
    for (var block : blocks) {
      if (!block.isInitialized()) continue;
      memory.update(
          (address(block.getStart()) + ":" + block.getSize() + "\n")
              .getBytes(StandardCharsets.UTF_8));
      for (long offset = 0; offset < block.getSize(); offset += buffer.length) {
        monitor.checkCancelled();
        int length = (int) Math.min(buffer.length, block.getSize() - offset);
        int read = p.getMemory().getBytes(block.getStart().add(offset), buffer, 0, length);
        if (read != length)
          throw new java.io.IOException("Incomplete fingerprint read at " + block.getStart());
        memory.update(buffer, 0, length);
      }
    }
    parts.put("memory", HexFormat.of().formatHex(memory.digest()));
    var data = new ArrayList<String>();
    for (var unit : p.getListing().getDefinedData(true)) {
      monitor.checkCancelled();
      data.add(
          address(unit.getAddress())
              + ":"
              + unit.getLength()
              + ":"
              + unit.getDataType().getPathName());
    }
    Collections.sort(data);
    parts.put(
        "data", Sha256.of(String.join("\n", data).getBytes(StandardCharsets.UTF_8)).toString());
    var instructions = new ArrayList<String>();
    for (var ins : p.getListing().getInstructions(true)) {
      monitor.checkCancelled();
      instructions.add(
          address(ins.getAddress())
              + ":"
              + ins.getLength()
              + ":"
              + ins.getFlowOverride()
              + ":"
              + ins.isFallThroughOverridden()
              + ":"
              + address(ins.getFallThrough()));
    }
    Collections.sort(instructions);
    parts.put(
        "instructions",
        Sha256.of(String.join("\n", instructions).getBytes(StandardCharsets.UTF_8)).toString());
    return Collections.unmodifiableMap(parts);
  }

  public static String capture(Program p, TaskMonitor monitor) throws Exception {
    return Sha256.of(
            ProgramMapping.JSON.toJson(components(p, monitor)).getBytes(StandardCharsets.UTF_8))
        .toString();
  }

  public static void requireCurrent(Program p, AnalysisResult result, TaskMonitor monitor)
      throws Exception {
    if (result == null
        || result.schemaVersion() != 2
        || !AnalysisResult.ENGINE_VERSION.equals(result.engineVersion())
        || !capture(p, monitor).equals(result.fingerprint()))
      throw new IllegalStateException(
          "Analysis is stale or unversioned; preview again after code, mapping or flow changes");
  }
}
