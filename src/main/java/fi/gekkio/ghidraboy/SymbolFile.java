package fi.gekkio.ghidraboy;

import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

/** RGBDS Game Boy .sym format; deliberately not WLA-DX or .map. */
public final class SymbolFile {
  public record Location(String form, long bank, int address) {}

  public record Symbol(Location location, String name, int line) {}

  public record Result(List<Symbol> symbols, List<String> diagnostics) {}

  private static final Pattern NAME =
      Pattern.compile("[A-Za-z_]([A-Za-z0-9_@#$.]|\\\\u[A-Fa-f0-9]{4}|\\\\U[A-Fa-f0-9]{8})*");

  private SymbolFile() {}

  public static Result parse(byte[] bytes) throws java.nio.charset.CharacterCodingException {
    String input =
        StandardCharsets.UTF_8
            .newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString();
    var symbols = new ArrayList<Symbol>();
    var warnings = new ArrayList<String>();
    var seen = new HashSet<String>();
    int line = 0;
    for (String raw : input.split("\\r?\\n", -1)) {
      line++;
      String text = raw.split(";", 2)[0].replaceAll("^[ \\t]+|[ \\t]+$", "");
      if (text.isEmpty()) continue;
      String[] tokens = text.split("[ \\t]+");
      if (tokens.length < 2) {
        warnings.add(line + ": reserved single-token line ignored");
        continue;
      }
      try {
        String[] parts = tokens[0].split(":", -1);
        if (parts.length > 2) throw new IllegalArgumentException("Invalid location form");
        String form =
            parts.length == 1 ? "ANY" : parts[0].equalsIgnoreCase("BOOT") ? "BOOT" : "BANK";
        long bank = form.equals("BANK") ? hex(parts[0], 0xffffffffL) : 0;
        int address = (int) hex(parts[parts.length - 1], 0xffff);
        String name = tokens[1];
        if (!NAME.matcher(name).matches())
          throw new IllegalArgumentException("Invalid name/escape");
        var escape = Pattern.compile("\\\\([uU])([A-Fa-f0-9]+)").matcher(name);
        while (escape.find()) {
          int digits = escape.group(1).equals("u") ? 4 : 8;
          long value = Long.parseLong(escape.group(2).substring(0, digits), 16);
          if (value < 0xa0 || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff))
            throw new IllegalArgumentException("Invalid Unicode scalar escape");
        }
        var decoded = new StringBuilder();
        for (int at = 0; at < name.length(); ) {
          if (name.charAt(at) == '\\') {
            int digits = name.charAt(at + 1) == 'u' ? 4 : 8;
            decoded.appendCodePoint(Integer.parseInt(name.substring(at + 2, at + 2 + digits), 16));
            at += 2 + digits;
          } else decoded.append(name.charAt(at++));
        }
        name = decoded.toString();
        if (name.startsWith(".")
            || name.endsWith(".")
            || name.chars().filter(c -> c == '.').count() > 1)
          throw new IllegalArgumentException("Empty or nested local label unsupported");
        var location = new Location(form, bank, address);
        String key = location + "\n" + name;
        if (seen.add(key)) symbols.add(new Symbol(location, name, line));
        for (int i = 2; i < tokens.length; i++)
          if (!tokens[i].startsWith("@")) warnings.add(line + ": unknown metadata " + tokens[i]);
      } catch (IllegalArgumentException e) {
        warnings.add(line + ": " + e.getMessage());
      }
    }
    return new Result(List.copyOf(symbols), List.copyOf(warnings));
  }

  private static long hex(String text, long max) {
    if (!text.matches("[A-Fa-f0-9]+"))
      throw new IllegalArgumentException("Invalid hexadecimal location");
    long value = Long.parseUnsignedLong(text, 16);
    if (value < 0 || value > max) throw new IllegalArgumentException("Location out of range");
    return value;
  }

  public static String format(Collection<Symbol> symbols) {
    StringBuilder out = new StringBuilder();
    for (var s : symbols) {
      var l = s.location;
      if (l.form.equals("BOOT")) out.append("BOOT:");
      else if (l.form.equals("BANK")) out.append(Long.toHexString(l.bank)).append(':');
      out.append(String.format(Locale.ROOT, "%04x", l.address))
          .append(' ')
          .append(encodeName(s.name))
          .append('\n');
    }
    return out.toString();
  }

  public static String encodeName(String name) {
    var out = new StringBuilder();
    name.codePoints()
        .forEach(
            cp -> {
              if (cp >= 0xa0 && !(cp >= 0xd800 && cp <= 0xdfff))
                out.append(String.format(Locale.ROOT, cp <= 0xffff ? "\\u%04x" : "\\U%08x", cp));
              else out.appendCodePoint(cp);
            });
    return out.toString();
  }

  public static Optional<Symbol> parent(Symbol local, List<Symbol> all) {
    int dot = local.name.indexOf('.');
    if (dot < 0) return Optional.empty();
    return all.stream()
        .filter(
            s ->
                s.name.equals(local.name.substring(0, dot))
                    && s.location.form.equals(local.location.form)
                    && s.location.bank == local.location.bank
                    && s.location.address <= local.location.address)
        .max(Comparator.comparingInt(s -> s.location.address));
  }
}
