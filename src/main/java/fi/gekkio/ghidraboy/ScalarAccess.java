package fi.gekkio.ghidraboy;

import java.util.Objects;
import java.util.Optional;

/**
 * Internal resolution of one already ordered byte access. Width and byteIndex identify its
 * enclosing architectural operation; callers retain byte sequencing and 16-bit wrapping.
 * A mapping is not a byte value, and FETCH does not establish executable backing or decode.
 * Concrete resolution and transitions belong exclusively to MapperKnowledge/MapperState.
 */
final class ScalarAccess {
  private ScalarAccess() {}

  enum Kind { READ, WRITE, FETCH }

  record Request(Integer cpu, Kind kind, int width, int byteIndex, String source,
      int operation, int operand, Integer writtenValue) {
    Request {
      Objects.requireNonNull(kind);
      if (cpu != null && (cpu < 0 || cpu > 65535))
        throw new IllegalArgumentException("CPU address out of range");
      if (width < 1 || byteIndex < 0 || byteIndex >= width)
        throw new IllegalArgumentException("Invalid byte position in access");
      if (kind != Kind.WRITE && writtenValue != null)
        throw new IllegalArgumentException("Only writes carry a written value");
    }
    boolean pointerKnown() { return cpu != null; }
  }

  record Outcome(Request request, MapperKnowledge before, Optional<MapperKnowledge> after,
      Optional<MapperState.Resolution> resolution) {}

  static Outcome resolve(Cartridge cartridge, MapperKnowledge before, Request request) {
    Objects.requireNonNull(cartridge);
    Objects.requireNonNull(before);
    Objects.requireNonNull(request);
    if (!request.pointerKnown()) {
      // No address means no resolver call. In particular, an unlocated write has no established
      // post-state: do not assert it is neutral or invent a write to a representative address.
      return new Outcome(request, before,
          request.kind() == Kind.WRITE ? Optional.empty() : Optional.of(before), Optional.empty());
    }
    var resolution = before.translate(cartridge, request.cpu(), request.kind() == Kind.WRITE);
    var after = request.kind() == Kind.WRITE
        ? before.write(cartridge, request.cpu(), request.writtenValue()) : before;
    return new Outcome(request, before, Optional.of(after), Optional.of(resolution));
  }
}
