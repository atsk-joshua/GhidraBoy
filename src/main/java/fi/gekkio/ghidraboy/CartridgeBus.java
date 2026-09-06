package fi.gekkio.ghidraboy;

import ghidra.program.model.lang.Language;
import ghidra.program.model.pcode.PcodeOp;

/** Direct-write hook identities shared by injection, CPU execution and analysis. */
public final class CartridgeBus {
  public static final String DIRECT_WRITE8 = "gb_direct_write8";
  public static final String DIRECT_WRITE16 = "gb_direct_write16";
  public static final String CARTRIDGE_WRITE8 = "gb_cartridge_write8";

  private CartridgeBus() {}

  /** Includes ROM_ONLY's ignored writes; RAW never establishes a cartridge control model. */
  public static boolean supportsControls(Cartridge cartridge) {
    return cartridge != null
        && cartridge.mapper() != null
        && cartridge.mapper() != Cartridge.Mapper.RAW;
  }

  public static int userop(Language language, String name) {
    for (int i = 0; i < language.getNumberOfUserDefinedOpNames(); i++)
      if (name.equals(language.getUserDefinedOpName(i))) return i;
    throw new IllegalArgumentException("Missing bus userop: " + name);
  }

  public static boolean isDirectWrite(Language language, PcodeOp op) {
    if (op.getOpcode() != PcodeOp.CALLOTHER
        || op.getNumInputs() != 3
        || !op.getInput(0).isConstant()) return false;
    long index = op.getInput(0).getOffset();
    if (index < 0 || index >= language.getNumberOfUserDefinedOpNames()) return false;
    String name = language.getUserDefinedOpName((int) index);
    return DIRECT_WRITE8.equals(name) || DIRECT_WRITE16.equals(name);
  }
}
