package fi.gekkio.ghidraboy;

/**
 * Independent known/unknown mapper registers; representative defaults are never exposed as facts.
 */
public record MapperKnowledge(
    Integer low,
    Integer high,
    Integer mode,
    Integer ram,
    Boolean enabled,
    Integer vbk,
    Integer svbk,
    Integer latch) {
  public static MapperKnowledge unknown() {
    return new MapperKnowledge(null, null, null, null, null, null, null, null);
  }

  public static MapperKnowledge from(MapperState s) {
    return s == null
        ? unknown()
        : new MapperKnowledge(
            s.romLow(),
            s.romHigh(),
            s.mode(),
            s.ramSelect(),
            s.ramEnabled(),
            s.vbk(),
            s.svbk(),
            s.latch());
  }

  /**
   * Adds only selector facts established by the physical execution view containing an entry.
   * Fields unrelated to that fetch remain unknown.
   */
  public MapperKnowledge constrainEntry(
      Cartridge cartridge, MapperState.Physical physical, int cpu) {
    if (physical == null) return this;
    var derived = unknown();
    switch (physical.region()) {
      case "ROM" -> {
        if (cpu < 0 || cpu >= 0x8000)
          throw new IllegalArgumentException("ROM entry is outside the CPU ROM windows");
        if (cpu < 0x4000) {
          if (physical.bank() != 0 && cartridge.mapper() != Cartridge.Mapper.MBC1)
            throw new IllegalArgumentException("Physical ROM entry conflicts with fixed ROM window");
        } else {
          switch (cartridge.mapper()) {
            case MBC5 ->
                derived =
                    new MapperKnowledge(
                        physical.bank() & 0xff,
                        cartridge.actualRomBanks() > 256 ? (physical.bank() >>> 8) & 1 : null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null);
            case MBC2, MBC3 -> {
              // Effective bank 1 can result from more than one raw selector value.
              if (physical.bank() != 1)
                derived =
                    new MapperKnowledge(
                        physical.bank(), null, null, null, null, null, null, null);
            }
            case ROM_ONLY -> {
              if (physical.bank() != 1)
                throw new IllegalArgumentException("Physical ROM entry conflicts with ROM-only window");
            }
            case MBC1, RAW -> {
              // MBC1 coupled wiring and RAW have no single safe scalar selector premise here.
            }
          }
        }
      }
      case "VRAM" ->
          derived =
              new MapperKnowledge(null, null, null, null, null, physical.bank(), null, null);
      case "WRAM" -> {
        if (physical.bank() > 1)
          derived =
              new MapperKnowledge(null, null, null, null, null, null, physical.bank(), null);
      }
      case "SRAM", "MBC2_RAM" ->
          derived =
              new MapperKnowledge(
                  null,
                  null,
                  null,
                  physical.region().equals("SRAM") ? physical.bank() : null,
                  true,
                  null,
                  null,
                  null);
      case "HRAM", "OAM", "IO", "IE", "DEVICE" -> {}
      default -> throw new IllegalArgumentException("Unsupported physical execution region " + physical.region());
    }
    return merge(derived);
  }

  public MapperKnowledge merge(MapperKnowledge other) {
    return new MapperKnowledge(
        merge("ROM low selector", low, other.low),
        merge("ROM high selector", high, other.high),
        merge("mapper mode", mode, other.mode),
        merge("RAM selector", ram, other.ram),
        merge("RAM enabled state", enabled, other.enabled),
        merge("VBK", vbk, other.vbk),
        merge("SVBK", svbk, other.svbk),
        merge("RTC latch", latch, other.latch));
  }

  private static <T> T merge(String name, T a, T b) {
    if (a != null && b != null && !a.equals(b))
      throw new IllegalArgumentException("Physical entry view contradicts explicit " + name);
    return a != null ? a : b;
  }

  private MapperState representative() {
    return new MapperState(
        low == null ? 1 : low,
        high == null ? 0 : high,
        mode == null ? 0 : mode,
        ram == null ? 0 : ram,
        enabled != null && enabled,
        vbk == null ? 0 : vbk,
        svbk == null ? 1 : svbk,
        latch == null ? 0 : latch);
  }

  public MapperKnowledge write(Cartridge c, int address, Integer value) {
    var s = representative().write(c, address, value == null ? 0 : value);
    Integer l = low, h = high, m = mode, r = ram, v = vbk, w = svbk, t = latch;
    Boolean e = enabled;
    if (address == 0xff4f) v = value == null ? null : s.vbk();
    if (address == 0xff70) w = value == null ? null : s.svbk();
    switch (c.mapper()) {
      case MBC1 -> {
        if (address < 0x2000) e = value == null ? null : s.ramEnabled();
        else if (address < 0x4000) l = value == null ? null : s.romLow();
        else if (address < 0x6000) {
          h = value == null ? null : s.romHigh();
          r = value == null ? null : s.ramSelect();
        } else if (address < 0x8000) m = value == null ? null : s.mode();
      }
      case MBC2 -> {
        if (address < 0x4000) {
          if ((address & 0x100) == 0) e = value == null ? null : s.ramEnabled();
          else l = value == null ? null : s.romLow();
        }
      }
      case MBC3 -> {
        if (address < 0x2000) e = value == null ? null : s.ramEnabled();
        else if (address < 0x4000) l = value == null ? null : s.romLow();
        else if (address < 0x6000) r = value == null ? null : s.ramSelect();
        else if (address < 0x8000) t = value;
      }
      case MBC5 -> {
        if (address < 0x2000) e = value == null ? null : s.ramEnabled();
        else if (address < 0x3000) l = value;
        else if (address < 0x4000) h = value == null ? null : s.romHigh();
        else if (address < 0x6000) r = value == null ? null : s.ramSelect();
      }
      default -> {}
    }
    return new MapperKnowledge(l, h, m, r, e, v, w, t);
  }

  public MapperState.Resolution translate(Cartridge c, int cpu, boolean write) {
    if (cpu < 0 || cpu > 65535) throw new IllegalArgumentException("CPU address out of range");
    boolean missing = false;
    if (!write && cpu < 0x8000) {
      missing =
          switch (c.mapper()) {
            case MBC1 ->
                cpu < 0x4000
                    ? c.actualRomBanks() > 32 && (mode == null || (mode == 1 && high == null))
                    : low == null || (c.actualRomBanks() > 32 && high == null);
            case MBC2, MBC3 -> cpu >= 0x4000 && low == null;
            case MBC5 ->
                cpu >= 0x4000 && (low == null || (c.actualRomBanks() > 256 && high == null));
            default -> false;
          };
    } else if (cpu >= 0x8000 && cpu < 0xa000 && c.color()) missing = vbk == null;
    else if (cpu >= 0xa000
        && cpu < 0xc000
        && c.mapper() != Cartridge.Mapper.ROM_ONLY
        && c.mapper() != Cartridge.Mapper.RAW) {
      missing = enabled == null;
      if (Boolean.TRUE.equals(enabled))
        missing |=
            switch (c.mapper()) {
              case MBC1 -> mode == null || (mode == 1 && high == null);
              case MBC3, MBC5 -> ram == null;
              default -> false;
            };
    } else if (c.color() && ((cpu >= 0xd000 && cpu < 0xe000) || (cpu >= 0xf000 && cpu < 0xfe00)))
      missing = svbk == null;
    if (missing)
      return MapperState.Resolution.other("unknown", "Required mapper register is unknown");
    return MapperState.translate(c, representative(), cpu, write);
  }

  public boolean allowsExecution(Cartridge c, int cpu, int bank) {
    int lowMax =
        switch (c.mapper()) {
          case MBC1 -> 31;
          case MBC2 -> 15;
          case MBC3 -> 127;
          case MBC5 -> 255;
          default -> 0;
        };
    int highMax =
        c.mapper() == Cartridge.Mapper.MBC1 ? 3 : c.mapper() == Cartridge.Mapper.MBC5 ? 1 : 0;
    for (int l = low == null ? 0 : low; l <= (low == null ? lowMax : low); l++)
      for (int h = high == null ? 0 : high; h <= (high == null ? highMax : high); h++)
        for (int m = mode == null ? 0 : mode; m <= (mode == null ? 1 : mode); m++) {
          var physical =
              MapperState.translate(c, new MapperState(l, h, m, 0, false, 0, 1, 0), cpu, false)
                  .physical();
          if (physical != null && physical.region().equals("ROM") && physical.bank() == bank)
            return true;
        }
    return false;
  }
}
