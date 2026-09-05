package fi.gekkio.ghidraboy;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

/** Invalidation dependency: mapped bytes, topology, data markings and instruction overrides. */
public final class ProgramFingerprint {
    private ProgramFingerprint() { }
    public static String capture(Program p, TaskMonitor monitor) throws Exception {
        var digest = MessageDigest.getInstance("SHA-256");
        digest.update(ProgramMapping.JSON.toJson(ProgramMapping.inspect(p)).getBytes(StandardCharsets.UTF_8));
        byte[] buffer = new byte[16384];
        for (var block : p.getMemory().getBlocks()) {
            if (!block.isInitialized()) continue;
            for (long offset = 0; offset < block.getSize(); offset += buffer.length) {
                monitor.checkCancelled();
                int length = (int)Math.min(buffer.length, block.getSize()-offset);
                int read = p.getMemory().getBytes(block.getStart().add(offset), buffer, 0, length);
                if (read != length) throw new java.io.IOException("Incomplete fingerprint read at " + block.getStart());
                digest.update(buffer, 0, length);
            }
        }
        for (var data : p.getListing().getDefinedData(true)) {
            monitor.checkCancelled();
            digest.update((data.getAddress()+":"+data.getLength()+":"+data.getDataType().getPathName()+"\n").getBytes(StandardCharsets.UTF_8));
        }
        for (var ins : p.getListing().getInstructions(true)) {
            monitor.checkCancelled();
            digest.update((ins.getAddress()+":"+ins.getLength()+":"+ins.getFlowOverride()+":"+ins.getFallThrough()+"\n").getBytes(StandardCharsets.UTF_8));
        }
        return HexFormat.of().formatHex(digest.digest());
    }
    public static void requireCurrent(Program p, AnalysisResult result, TaskMonitor monitor) throws Exception {
        if (result == null || result.schemaVersion() != 2 || !capture(p, monitor).equals(result.fingerprint()))
            throw new IllegalStateException("Analysis is stale or unversioned; preview again after code, mapping or flow changes");
    }
}
