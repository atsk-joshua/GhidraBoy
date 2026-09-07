package fi.gekkio.ghidraboy;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.util.ArrayList;
import java.util.List;

/** Strict public JSON boundary: an omitted primitive premise must never become a known zero. */
public final class SoftwareCallConfiguration {
  private SoftwareCallConfiguration() {}

  public static List<SoftwareCallValidation.Configuration> read(String json) {
    var root = JsonParser.parseString(json);
    if (!root.isJsonArray()) throw new IllegalArgumentException("Software-call configurations must be an array");
    var result = new ArrayList<SoftwareCallValidation.Configuration>();
    for (var value : root.getAsJsonArray()) result.add(readOne(value));
    if (result.isEmpty()) throw new IllegalArgumentException("No software-call configurations supplied");
    return List.copyOf(result);
  }

  static SoftwareCallValidation.Configuration readOne(JsonElement value) {
    var root = object(value, "configuration");
    integer(root, "callCpu", "configuration");
    integer(root, "callerSp", "configuration");
    string(root, "transfer", "configuration");
    var template = object(required(root, "template", "configuration"), "template");
    String family = string(template, "family", "template");
    integer(template, "helperCpu", "template");
    integer(template, "payloadLength", "template");
    if (family.equals("CONSTANT_REGISTER_JP")) integer(template, "constantRaw", "template");
    var registers = object(required(root, "registers", "configuration"), "registers");
    for (var key : List.of("a", "f", "bc", "de", "hl")) integer(registers, key, "registers");
    var mapper = object(required(root, "mapper", "configuration"), "mapper");
    for (var key : List.of("romLow", "romHigh", "mode", "ramSelect", "vbk", "svbk", "latch"))
      integer(mapper, key, "mapper");
    var enabled = required(mapper, "ramEnabled", "mapper");
    if (!enabled.isJsonPrimitive() || !enabled.getAsJsonPrimitive().isBoolean())
      throw new IllegalArgumentException("mapper.ramEnabled must be an explicit boolean");
    return ProgramMapping.JSON.fromJson(root, SoftwareCallValidation.Configuration.class);
  }

  private static JsonElement required(JsonObject object, String key, String path) {
    if (!object.has(key) || object.get(key).isJsonNull())
      throw new IllegalArgumentException("Missing required software-call premise: " + path + "." + key);
    return object.get(key);
  }
  private static JsonObject object(JsonElement value, String path) {
    if (value == null || !value.isJsonObject()) throw new IllegalArgumentException(path + " must be an object");
    return value.getAsJsonObject();
  }
  private static void integer(JsonObject object, String key, String path) {
    var value = required(object, key, path);
    if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isNumber())
      throw new IllegalArgumentException(path + "." + key + " must be an explicit integer");
    try { value.getAsBigDecimal().intValueExact(); }
    catch (ArithmeticException invalid) { throw new IllegalArgumentException(path + "." + key + " must fit an integer", invalid); }
  }
  private static String string(JsonObject object, String key, String path) {
    var value = required(object, key, path);
    if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString())
      throw new IllegalArgumentException(path + "." + key + " must be a string");
    return value.getAsString();
  }
}
