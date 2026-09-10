package fi.gekkio.ghidraboy;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.*;

/** Versioned static contract. All lookups use the Program's actual address factory and sources. */
public final class ProgramMapping {
  public static final int SCHEMA_VERSION = 2;
  public static final String OPTIONS = "GhidraBoy";
  private static final String ANCHORS = "GhidraBoy.Physical";
  public static final Gson JSON =
      new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();
  private static final Map<FileBytes, String> HASHES =
      Collections.synchronizedMap(new WeakHashMap<>());

  private ProgramMapping() {}

  public record Range(
      String region,
      int bank,
      long offset,
      long length,
      String space,
      long start,
      Long fileOffset,
      String alias,
      boolean read,
      boolean write,
      boolean execute,
      String provenance) {}

  public record Snapshot(
      int schemaVersion,
      String language,
      String compiler,
      Cartridge cartridge,
      String inputMode,
      long originalLength,
      String originalSha256,
      Cartridge.Support support,
      List<Range> ranges,
      List<String> diagnostics,
      RequestProvenance request,
      List<UnmappedFileRange> originalUnmapped) {}

  public record RequestProvenance(
      String requestedMode,
      String selectedMode,
      String mapperOverride,
      String selectedMapper,
      String hardware,
      String hardwareSource) {}

  public record UnmappedFileRange(long offset, long length, String reason) {}

  private record Anchor(String region, int bank, long length, long offset, String origin) {}

  public static void anchor(Program p, MemoryBlock b, String region, int bank) throws Exception {
    var map = p.getUsrPropertyManager().getStringPropertyMap(ANCHORS);
    if (map == null) map = p.getUsrPropertyManager().createStringPropertyMap(ANCHORS);
    map.add(b.getStart(), JSON.toJson(new Anchor(region, bank, b.getSize(), 0, "loader-anchor")));
  }

  public static void identifyRam(
      Program p,
      Address start,
      long length,
      String region,
      int bank,
      long offset,
      TaskMonitor monitor)
      throws Exception {
    long bankSize =
        switch (region) {
          case "WRAM" -> 0x1000;
          case "VRAM", "SRAM" -> 0x2000;
          case "MBC2_RAM" -> 512;
          default -> throw new IllegalArgumentException("Expected WRAM, VRAM, SRAM or MBC2_RAM");
        };
    int maxBank =
        switch (region) {
          case "WRAM" -> 7;
          case "VRAM" -> 1;
          case "SRAM" -> 15;
          default -> 0;
        };
    if (length <= 0 || offset < 0 || offset + length > bankSize || bank < 0 || bank > maxBank)
      throw new IllegalArgumentException("Invalid physical RAM interval");
    var end = start.addNoWrap(length - 1);
    var block = p.getMemory().getBlock(start);
    if (block == null
        || !block.contains(end)
        || block.isMapped()
        || block.getSourceInfos().stream().anyMatch(info -> info.getFileBytes().isPresent()))
      throw new IllegalArgumentException(
          "Identify a contiguous canonical RAM interval, not ROM or an alias");
    var map = p.getUsrPropertyManager().getStringPropertyMap(ANCHORS);
    var desired = new Anchor(region, bank, length, offset, "explicit-anchor");
    if (map != null) {
      var iterator = map.getPropertyIterator();
      while (iterator.hasNext()) {
        monitor.checkCancelled();
        var a = iterator.next();
        var existing = JSON.fromJson(map.getString(a), Anchor.class);
        if (a.equals(start)
            && desired.region.equals(existing.region)
            && desired.bank == existing.bank
            && desired.length == existing.length
            && desired.offset == existing.offset) return;
        boolean staticOverlap =
            a.getAddressSpace().equals(start.getAddressSpace())
                && start.getOffset() < a.getOffset() + existing.length
                && a.getOffset() < start.getOffset() + length;
        boolean physicalOverlap =
            region.equals(existing.region)
                && bank == existing.bank
                && offset < existing.offset + existing.length
                && existing.offset < offset + length;
        if (staticOverlap || physicalOverlap)
          throw new IllegalArgumentException("Conflicting existing RAM identity at " + a);
      }
    }
    int tx = p.startTransaction("Identify legacy RAM physical interval");
    boolean success = false;
    try {
      if (map == null) map = p.getUsrPropertyManager().createStringPropertyMap(ANCHORS);
      map.add(start, JSON.toJson(desired));
      monitor.checkCancelled();
      success = true;
    } finally {
      p.endTransaction(tx, success);
    }
  }

  /**
   * Exact static-space lookup: overlay getAddress(long) otherwise falls back outside mapped ranges.
   */
  public static Address staticAddress(Program p, String text) {
    int separator = text.lastIndexOf("::");
    if (separator >= 0) {
      var space = p.getAddressFactory().getAddressSpace(text.substring(0, separator));
      if (space == null) return null;
      try {
        return space.getAddressInThisSpaceOnly(
            Long.parseUnsignedLong(text.substring(separator + 2), 16));
      } catch (IllegalArgumentException error) {
        return null;
      }
    }
    return p.getAddressFactory().getAddress(text);
  }

  public static Cartridge cartridge(Program p) {
    String value = p.getOptions(OPTIONS).getString("cartridge", null);
    return value == null ? null : JSON.fromJson(value, Cartridge.class);
  }

  public static FileBytes originalFile(Program p) throws IOException {
    var files = p.getMemory().getAllFileBytes();
    if (files.size() != 1)
      throw new IOException("Expected exactly one original input; found " + files.size());
    var file = files.get(0);
    if (file.getFileOffset() != 0 || file.getSize() > 0x1000000)
      throw new IOException("Uncertain file provenance or oversized input");
    return file;
  }

  public static Snapshot inspect(Program p) throws IOException {
    var file = originalFile(p);
    var opts = p.getOptions(OPTIONS);
    List<Range> ranges = new ArrayList<>();
    List<String> diagnostics = new ArrayList<>();
    var anchors = p.getUsrPropertyManager().getStringPropertyMap(ANCHORS);
    boolean boot = opts.getString("inputMode", "CARTRIDGE").contains("BOOT");
    for (var block : p.getMemory().getBlocks()) {
      for (var source : block.getSourceInfos()) {
        long f = source.getFileBytesOffset();
        if (f >= 0 && source.getFileBytes().orElse(null) == file) {
          long consumed = 0;
          while (consumed < source.getLength()) {
            long at = f + consumed;
            long length = Math.min(source.getLength() - consumed, 0x4000 - at % 0x4000);
            ranges.add(
                range(
                    block,
                    boot ? "BOOT" : "ROM",
                    boot ? 0 : (int) (at / 0x4000),
                    boot ? at : at % 0x4000,
                    length,
                    source.getMinAddress().add(consumed),
                    at,
                    null,
                    "file-source"));
            consumed += length;
          }
        } else if (source.getMappedRange().isPresent()) {
          if (block.getType() != ghidra.program.model.mem.MemoryBlockType.BYTE_MAPPED
              || source
                  .getByteMappingScheme()
                  .map(scheme -> !scheme.isOneToOneMapping())
                  .orElse(false)) {
            diagnostics.add("Unsupported complex mapping: " + source.getMinAddress());
            continue;
          }
          var target = source.getMappedRange().get().getMinAddress();
          ranges.add(
              range(
                  block,
                  "ALIAS",
                  -1,
                  0,
                  source.getLength(),
                  source.getMinAddress(),
                  null,
                  target.toString(),
                  "byte-mapping"));
        } else if (anchors != null) {
          boolean found = false;
          var it = anchors.getPropertyIterator();
          while (it.hasNext()) {
            var a = it.next();
            var anchor = JSON.fromJson(anchors.getString(a), Anchor.class);
            if (a.getAddressSpace().equals(source.getMinAddress().getAddressSpace())) {
              long lo = Math.max(a.getOffset(), source.getMinAddress().getOffset());
              long hi =
                  Math.min(a.getOffset() + anchor.length, source.getMaxAddress().getOffset() + 1);
              if (lo < hi) {
                ranges.add(
                    range(
                        block,
                        anchor.region,
                        anchor.bank,
                        anchor.offset + lo - a.getOffset(),
                        hi - lo,
                        a.getAddressSpace().getAddress(lo),
                        null,
                        null,
                        anchor.origin == null ? "legacy-anchor" : anchor.origin));
                found = true;
              }
            }
          }
          if (!found) diagnostics.add("Unresolved physical identity: " + source.getMinAddress());
        } else diagnostics.add("Legacy block needs explicit mapping: " + source.getMinAddress());
      }
    }
    ranges.sort(
        Comparator.comparing(Range::region)
            .thenComparingInt(Range::bank)
            .thenComparingLong(Range::offset)
            .thenComparing(Range::space)
            .thenComparingLong(Range::start));
    String hash = HASHES.get(file);
    if (hash == null) {
      byte[] original = new byte[(int) file.getSize()];
      file.getOriginalBytes(0, original);
      hash = Sha256.of(original).toString();
      HASHES.put(file, hash);
    }
    var cartridge = cartridge(p);
    var unmapped = new ArrayList<UnmappedFileRange>();
    if (cartridge != null && cartridge.addressableLength() < file.getSize())
      unmapped.add(
          new UnmappedFileRange(
              cartridge.addressableLength(),
              file.getSize() - cartridge.addressableLength(),
              "SALVAGE_UNMAPPED"));
    else if (opts.getString("inputMode", "").equals("CGB_BOOT"))
      unmapped.add(new UnmappedFileRange(0x100, 0x100, "BOOT_HOLE"));
    var request =
        new RequestProvenance(
            opts.getString("requestedMode", "LEGACY_UNKNOWN"),
            opts.getString("inputMode", "LEGACY_UNKNOWN"),
            opts.getString("mapperOverride", "AUTO"),
            cartridge == null ? "NOT_APPLICABLE" : cartridge.mapper().name(),
            opts.getString("hardware", "UNKNOWN"),
            opts.getString(
                "hardwareProvenance", "loader option or unrecovered historical selection"));
    return new Snapshot(
        SCHEMA_VERSION,
        p.getLanguageID().toString(),
        p.getCompilerSpec().getCompilerSpecID().toString(),
        cartridge(p),
        opts.getString("inputMode", "LEGACY_UNKNOWN"),
        file.getSize(),
        hash,
        cartridge(p) == null ? null : cartridge(p).support(),
        List.copyOf(ranges),
        List.copyOf(diagnostics),
        request,
        List.copyOf(unmapped));
  }

  private static Range range(
      MemoryBlock b,
      String region,
      int bank,
      long off,
      long len,
      Address a,
      Long file,
      String alias,
      String provenance) {
    return new Range(
        region,
        bank,
        off,
        len,
        a.getAddressSpace().getName(),
        a.getOffset(),
        file,
        alias,
        b.isRead(),
        b.isWrite(),
        b.isExecute(),
        provenance);
  }

  public static List<Address> physicalToStatic(Program p, MapperState.Physical physical)
      throws IOException {
    if (physical.bank() < 0 || physical.offset() < 0)
      throw new IllegalArgumentException("Negative physical bank/offset");
    var snapshot = inspect(p);
    List<Address> out = new ArrayList<>();
    for (var r : snapshot.ranges())
      if (r.region.equals(physical.region())
          && r.bank == physical.bank()
          && physical.offset() >= r.offset
          && physical.offset() < r.offset + r.length)
        out.add(
            p.getAddressFactory()
                .getAddressSpace(r.space)
                .getAddress(r.start + physical.offset() - r.offset));
    return expandAliases(p, out, snapshot);
  }

  private static List<Address> expandAliases(Program p, List<Address> initial, Snapshot snapshot) {
    var out = new TreeSet<Address>(initial);
    var pending = new ArrayDeque<Address>(initial);
    while (!pending.isEmpty()) {
      var a = pending.removeFirst();
      for (var r : snapshot.ranges())
        if (r.alias != null) {
          Address target = p.getAddressFactory().getAddress(r.alias);
          if (target != null
              && a.getAddressSpace().equals(target.getAddressSpace())
              && a.getOffset() >= target.getOffset()
              && a.getOffset() < target.getOffset() + r.length) {
            var view =
                p.getAddressFactory()
                    .getAddressSpace(r.space)
                    .getAddress(r.start + a.getOffset() - target.getOffset());
            if (out.add(view)) pending.add(view);
          }
        }
    }
    return List.copyOf(out);
  }

  public static List<Address> fileToStatic(Program p, long offset) throws IOException {
    if (offset < 0) throw new IllegalArgumentException("Negative file offset");
    var snapshot = inspect(p);
    List<Address> out = new ArrayList<>();
    for (var r : snapshot.ranges())
      if (r.fileOffset != null && offset >= r.fileOffset && offset < r.fileOffset + r.length)
        out.add(
            p.getAddressFactory()
                .getAddressSpace(r.space)
                .getAddress(r.start + offset - r.fileOffset));
    return expandAliases(p, out, snapshot);
  }

  public static List<Long> staticToFile(Program p, Address address) throws IOException {
    var result = new TreeSet<Long>();
    for (var physical : staticToPhysical(p, address)) {
      if (physical.region().equals("ROM"))
        result.add(physical.bank() * 0x4000L + physical.offset());
      if (physical.region().equals("BOOT")) result.add((long) physical.offset());
    }
    return List.copyOf(result);
  }

  public record StaticResolution(
      String status, MapperState.Physical physical, List<Address> addresses, String reason) {}

  public static StaticResolution cpuToStatic(Program p, MapperState state, int cpu, boolean write)
      throws IOException {
    var c = cartridge(p);
    if (c == null)
      return new StaticResolution("unknown", null, List.of(), "No cartridge descriptor");
    var result = MapperState.translate(c, state, cpu, write);
    if (result.physical() == null)
      return new StaticResolution(result.status(), null, List.of(), result.reason());
    var views =
        physicalToStatic(p, result.physical()).stream().filter(a -> a.getOffset() == cpu).toList();
    return new StaticResolution(
        views.isEmpty() ? "unmapped" : views.size() > 1 ? "multiple-views" : "mapped",
        result.physical(),
        views,
        views.isEmpty() ? "Physical identity known but no static view" : "Explicit state");
  }

  public static List<MapperState.Physical> staticToPhysical(Program p, Address address)
      throws IOException {
    return staticToPhysical(p, address, inspect(p), new HashSet<>());
  }

  static List<MapperState.Physical> staticToPhysical(Program p, Address a, Snapshot snapshot)
      throws IOException {
    return staticToPhysical(p, a, snapshot, new HashSet<>());
  }

  private static List<MapperState.Physical> staticToPhysical(
      Program p, Address a, Snapshot snapshot, Set<Address> seen) throws IOException {
    if (!seen.add(a)) throw new IOException("Alias cycle at " + a);
    List<MapperState.Physical> out = new ArrayList<>();
    for (var r : snapshot.ranges())
      if (r.space.equals(a.getAddressSpace().getName())
          && a.getOffset() >= r.start
          && a.getOffset() < r.start + r.length) {
        long delta = a.getOffset() - r.start;
        if (r.alias != null) {
          Address target = p.getAddressFactory().getAddress(r.alias);
          if (target != null) out.addAll(staticToPhysical(p, target.add(delta), snapshot, seen));
        } else out.add(new MapperState.Physical(r.region, r.bank, (int) (r.offset + delta)));
      }
    return List.copyOf(out);
  }

  public static byte[] exportBytes(Program p, boolean current, boolean repair, TaskMonitor monitor)
      throws Exception {
    var file = originalFile(p);
    byte[] bytes = new byte[(int) file.getSize()];
    file.getOriginalBytes(0, bytes);
    if (current) {
      var snapshot = inspect(p);
      for (var block : p.getMemory().getBlocks())
        if (block.getStart().getOffset() < 0x8000 && !StockEntryInjection.presentationStorage(block)) {
          for (var source : block.getSourceInfos())
            if (source.getFileBytesOffset() < 0) {
              var identities = staticToPhysical(p, source.getMinAddress(), snapshot);
              if (identities.isEmpty()
                  || identities.stream()
                      .anyMatch(x -> !x.region().equals("ROM") && !x.region().equals("BOOT")))
                throw new IOException("Unresolved or detached ROM view: " + source.getMinAddress());
            }
        }
      boolean[] covered = new boolean[bytes.length];
      for (var block : p.getMemory().getBlocks())
        for (var source : block.getSourceInfos()) {
          monitor.checkCancelled();
          if (source.getFileBytes().orElse(null) != file || source.getFileBytesOffset() < 0)
            continue;
          int off = Math.toIntExact(source.getFileBytesOffset()),
              length = Math.toIntExact(source.getLength());
          byte[] mapped = new byte[length];
          p.getMemory().getBytes(source.getMinAddress(), mapped);
          for (int i = 0; i < length; i++) {
            if (covered[off + i] && bytes[off + i] != mapped[i])
              throw new IOException("Conflicting edits for file offset " + (off + i));
            bytes[off + i] = mapped[i];
            covered[off + i] = true;
          }
        }
      if (cartridge(p) != null)
        for (int i = 0; i < cartridge(p).addressableLength(); i++)
          if (!covered[i])
            throw new IOException("Missing cartridge source mapping at file offset " + i);
    }
    if (repair) {
      if (!current || cartridge(p) == null)
        throw new IOException("Checksum repair requires current cartridge export");
      if (cartridge(p).headerStatus() == Cartridge.HeaderStatus.TRUNCATED
          || cartridge(p).headerStatus() == Cartridge.HeaderStatus.UNKNOWN_SIZE)
        throw new IOException("Checksum repair requires established header and ROM extent");
      int h = 0, g = 0;
      for (int i = 0x134; i <= 0x14c; i++) h = (h - (bytes[i] & 255) - 1) & 255;
      bytes[0x14d] = (byte) h;
      for (int i = 0; i < cartridge(p).addressableLength(); i++)
        if (i != 0x14e && i != 0x14f) g = (g + (bytes[i] & 255)) & 65535;
      bytes[0x14e] = (byte) (g >> 8);
      bytes[0x14f] = (byte) g;
    }
    return bytes;
  }

  public static void export(
      Program p, Path path, boolean current, boolean repair, TaskMonitor monitor) throws Exception {
    byte[] bytes = exportBytes(p, current, repair, monitor);
    monitor.checkCancelled();
    Files.write(path, bytes, StandardOpenOption.CREATE_NEW);
  }
}
