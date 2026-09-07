package fi.gekkio.ghidraboy;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.InjectPayloadCallother;
import ghidra.program.model.lang.PcodeInjectLibrary;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import java.util.ArrayList;
import java.util.List;

/** Program-aware lowering of decoder-known direct writes; no instruction overrides. */
public final class CartridgeBusInjectLibrary extends PcodeInjectLibrary {
  public CartridgeBusInjectLibrary(SleighLanguage language) {
    super(language);
  }

  private CartridgeBusInjectLibrary(CartridgeBusInjectLibrary source) {
    super(source);
  }

  @Override
  public PcodeInjectLibrary clone() {
    return new CartridgeBusInjectLibrary(this);
  }

  @Override
  public InjectPayload allocateInject(String source, String name, int type) {
    if (type == InjectPayload.CALLMECHANISM_TYPE && SoftwareCallStateEntryInjection.NAME.equals(name))
      return new SoftwareCallStateEntryInjection(source, uniqueBase);
    if (type == InjectPayload.CALLFIXUP_TYPE && SoftwareCallInjection.NAME.equals(name))
      return new SoftwareCallInjection(source, uniqueBase);
    if (type == InjectPayload.CALLFIXUP_TYPE && SoftwareCallMayReturnInjection.NAME.equals(name))
      return new SoftwareCallMayReturnInjection(source);
    if (type == InjectPayload.CALLOTHERFIXUP_TYPE) {
      if (CartridgeBus.DIRECT_WRITE8.equals(name)) return new DirectWrite(source, 1, uniqueBase);
      if (CartridgeBus.DIRECT_WRITE16.equals(name)) return new DirectWrite(source, 2, uniqueBase);
    }
    return super.allocateInject(source, name, type);
  }

  private static final class DirectWrite extends InjectPayloadCallother {
    private final int width;
    private final long uniqueBase;

    DirectWrite(String source, int width, long uniqueBase) {
      super(source);
      this.width = width;
      this.uniqueBase = uniqueBase;
    }

    @Override
    public PcodeOp[] getPcode(Program program, InjectContext context) {
      if (context.inputlist.size() != 2
          || !context.inputlist.get(0).isConstant()
          || context.inputlist.get(0).getSize() != 2
          || context.inputlist.get(1).getSize() != width)
        throw new IllegalArgumentException(
            "Direct bus write requires encoded 16-bit address and expected value width");
      int cpu = (int) (context.inputlist.get(0).getOffset() & 0xffff);
      var value = context.inputlist.get(1);
      var constants = program.getAddressFactory().getConstantSpace();
      boolean cartridgeControls = CartridgeBus.supportsControls(ProgramMapping.cartridge(program));
      List<PcodeOp> ops = new ArrayList<>();
      Varnode[] bytes = new Varnode[width];
      // Capture both source bytes before either bus operation, preserving architectural ordering.
      for (int i = 0; i < width; i++) {
        if (width == 1) bytes[i] = value;
        else {
          bytes[i] =
              new Varnode(
                  program.getAddressFactory().getUniqueSpace().getAddress(uniqueBase + i), 1);
          ops.add(
              new PcodeOp(
                  context.baseAddr,
                  ops.size(),
                  PcodeOp.SUBPIECE,
                  new Varnode[] {value, new Varnode(constants.getAddress(i), 4)},
                  bytes[i]));
        }
      }
      for (int i = 0; i < width; i++) {
        int target = (cpu + i) & 0xffff;
        var address = new Varnode(constants.getAddress(target), 2);
        if (cartridgeControls && target < 0x8000) {
          var userop =
              new Varnode(
                  constants.getAddress(
                      CartridgeBus.userop(program.getLanguage(), CartridgeBus.CARTRIDGE_WRITE8)),
                  4);
          ops.add(
              new PcodeOp(
                  context.baseAddr,
                  ops.size(),
                  PcodeOp.CALLOTHER,
                  new Varnode[] {userop, address, bytes[i]}));
        } else {
          // Preserve ordinary flat/overlay memory semantics outside established controls.
          var space = context.baseAddr.getAddressSpace().getAddress(target).getAddressSpace();
          var spaceId = new Varnode(constants.getAddress(space.getSpaceID()), 8);
          ops.add(
              new PcodeOp(
                  context.baseAddr,
                  ops.size(),
                  PcodeOp.STORE,
                  new Varnode[] {spaceId, address, bytes[i]}));
        }
      }
      return ops.toArray(PcodeOp[]::new);
    }
  }
}
