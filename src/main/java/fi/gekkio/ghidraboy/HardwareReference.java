package fi.gekkio.ghidraboy;

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import java.util.Map;

/** Sources: gbdev/hardware.inc 189324b77f99cf287f4153e0001830e8738a4068 (CC0). */
public final class HardwareReference {
  private HardwareReference() {}

  private record Mask(long value, String description) {}

  private record Register(
      int address, String name, String description, boolean cgbOnly, Map<String, Mask> masks) {}

  private record Definitions(
      String source, String revision, String license, java.util.List<Register> registers) {}

  public static void apply(Program p, GameBoyKind kind) {
    apply(p, kind, false);
  }

  public static void apply(Program p, GameBoyKind kind, boolean newImport) {
    try (var stream = HardwareReference.class.getResourceAsStream("/hardware-registers.json")) {
      if (stream == null) throw new IllegalStateException("Packaged hardware definitions missing");
      var definitions =
          ProgramMapping.JSON.fromJson(
              new java.io.InputStreamReader(stream, java.nio.charset.StandardCharsets.UTF_8),
              Definitions.class);
      var as = p.getAddressFactory().getDefaultAddressSpace();
      for (var register : definitions.registers()) {
        if (register.cgbOnly() && kind != GameBoyKind.CGB) continue;
        var address = as.getAddress(register.address());
        if (p.getListing().getComment(CommentType.EOL, address) == null)
          p.getListing()
              .setComment(
                  address,
                  CommentType.EOL,
                  register.description() + " [hardware.inc " + definitions.revision() + "]");
        if (register.masks().isEmpty()) continue;
        var type =
            new EnumDataType(new CategoryPath("/GhidraBoy/Hardware"), register.name() + "Bits", 1);
        for (var mask : register.masks().entrySet())
          type.add(mask.getKey(), mask.getValue().value(), mask.getValue().description());
        var installed =
            p.getDataTypeManager().addDataType(type, DataTypeConflictHandler.KEEP_HANDLER);
        var data = p.getListing().getDataAt(address);
        if (newImport && data != null && data.getLength() == 1)
          ghidra.program.model.data.DataUtilities.createData(
              p,
              address,
              installed,
              -1,
              false,
              ghidra.program.model.data.DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
      }
    } catch (Exception error) {
      throw new IllegalStateException("Hardware reference installation failed", error);
    }

    var descriptions =
        Map.ofEntries(
            Map.entry(
                0xff00,
                "Joypad: bits 4/5 select active-low button groups; low four bits are active-low"
                    + " input."),
            Map.entry(0xff04, "DIV: divider read; writing any value resets the divider."),
            Map.entry(
                0xff07,
                "TAC: bit 2 timer enable; bits 1:0 select 4096/262144/65536/16384 Hz at normal"
                    + " speed."),
            Map.entry(
                0xff0f,
                "IF: interrupt requests; bits 0 VBlank, 1 LCD STAT, 2 timer, 3 serial, 4 joypad."),
            Map.entry(
                0xff40,
                "LCDC: 7 LCD enable, 6 window map, 5 window enable, 4 tile data, 3 BG map, 2 OBJ"
                    + " size, 1 OBJ enable, 0 BG/window enable (DMG) or priority (CGB)."),
            Map.entry(
                0xff41,
                "STAT: 6 LYC interrupt, 5 mode2 interrupt, 4 mode1 interrupt, 3 mode0 interrupt;"
                    + " read 2 coincidence and 1:0 PPU mode."),
            Map.entry(0xff44, "LY: current LCD scanline; timing is not modeled by static p-code."),
            Map.entry(
                0xff46, "DMA: writing starts OAM DMA from value << 8. No DMA execution model."),
            Map.entry(
                0xff4d,
                "CGB KEY1: bit7 current speed read; bit0 arm speed switch. STOP hardware sequencing"
                    + " is outside static semantics."),
            Map.entry(
                0xff4f,
                "CGB VBK: bit0 selects VRAM bank 0/1. Use explicit state for static translation."),
            Map.entry(
                0xff50,
                "BOOT: nonzero write disables boot-ROM mapping. No live selection is maintained."),
            Map.entry(
                0xff70,
                "CGB SVBK: bits2:0 select WRAM; zero selects bank1. Upper echo follows the same"
                    + " bank."),
            Map.entry(
                0xffff,
                "IE: enabled interrupts; bits0..4 VBlank, LCD STAT, timer, serial, joypad."));
    var as = p.getAddressFactory().getDefaultAddressSpace();
    for (var entry : descriptions.entrySet()) {
      int off = entry.getKey();
      if (kind != GameBoyKind.CGB && (off == 0xff4d || off == 0xff4f || off == 0xff70)) continue;
      var a = as.getAddress(off);
      if (p.getListing().getComment(CommentType.EOL, a) == null)
        p.getListing()
            .setComment(
                a,
                CommentType.EOL,
                entry.getValue() + " Reference: https://gbdev.io/pandocs/Hardware_Reg_List.html");
    }
    var masks = new EnumDataType(new CategoryPath("/GhidraBoy"), "InterruptMask", 1);
    masks.add("VBLANK", 1);
    masks.add("LCD_STAT", 2);
    masks.add("TIMER", 4);
    masks.add("SERIAL", 8);
    masks.add("JOYPAD", 16);
    p.getDataTypeManager().addDataType(masks, DataTypeConflictHandler.KEEP_HANDLER);
  }
}
