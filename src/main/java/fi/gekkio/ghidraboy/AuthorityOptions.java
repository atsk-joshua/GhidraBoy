package fi.gekkio.ghidraboy;

import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import java.util.Objects;

/** Public-API-only classification and mutation of persisted string authority. */
final class AuthorityOptions {
  enum FamilyState {
    ABSENT,
    STOCK,
    COMPANION,
    CONFLICT,
    AMBIGUOUS
  }

  record Family(FamilyState state, String stock, String companion) {
    boolean present(String description) {
      requireCoherent(description);
      return state == FamilyState.STOCK || state == FamilyState.COMPANION;
    }

    boolean stock(String description) {
      requireCoherent(description);
      return state == FamilyState.STOCK;
    }

    String value(String description) {
      requireCoherent(description);
      return state == FamilyState.STOCK ? stock : state == FamilyState.COMPANION ? companion : null;
    }

    void requireCoherent(String description) {
      if (state == FamilyState.AMBIGUOUS)
        throw new IllegalStateException("Ambiguous " + description + " authority; reopen the Program and retry");
      if (state == FamilyState.CONFLICT)
        throw new IllegalArgumentException(
            "Conflicting stock and companion " + description + " authority; records retained");
    }
  }

  private enum ValueState {
    ABSENT,
    PRESENT,
    AMBIGUOUS
  }

  private record Value(ValueState state, String value, Object defaultValue) {}

  private AuthorityOptions() {}

  private static Value classify(Program program, String list, String key) {
    if (!program.getOptionsNames().contains(list)) return new Value(ValueState.ABSENT, null, null);
    return classify(program.getOptions(list), key);
  }

  private static Value classify(Options options, String key) {
    if (!options.contains(key)) return new Value(ValueState.ABSENT, null, null);
    Object defaultValue = options.getDefaultValue(key);
    if (defaultValue != null && !(defaultValue instanceof String))
      return new Value(ValueState.AMBIGUOUS, null, defaultValue);
    String value = options.getString(key, null);
    if (defaultValue != null && Objects.equals(defaultValue, value))
      return new Value(ValueState.AMBIGUOUS, value, defaultValue);
    return new Value(value == null ? ValueState.ABSENT : ValueState.PRESENT, value, defaultValue);
  }

  static Family family(
      Program program,
      String stockList,
      String stockKey,
      String companionList,
      String companionKey) {
    return family(
        classify(program, stockList, stockKey), classify(program, companionList, companionKey));
  }

  static Family family(Options options, String stockKey, String companionKey) {
    return family(classify(options, stockKey), classify(options, companionKey));
  }

  private static Family family(Value stock, Value companion) {
    if (stock.state == ValueState.AMBIGUOUS || companion.state == ValueState.AMBIGUOUS)
      return new Family(FamilyState.AMBIGUOUS, stock.value, companion.value);
    boolean hasStock = stock.state == ValueState.PRESENT;
    boolean hasCompanion = companion.state == ValueState.PRESENT;
    if (hasStock && hasCompanion)
      return new Family(FamilyState.CONFLICT, stock.value, companion.value);
    if (hasStock) return new Family(FamilyState.STOCK, stock.value, null);
    if (hasCompanion) return new Family(FamilyState.COMPANION, null, companion.value);
    return new Family(FamilyState.ABSENT, null, null);
  }

  static String string(Program program, String list, String key) {
    return value(classify(program, list, key), key);
  }

  static String string(Options options, String key) {
    return value(classify(options, key), key);
  }

  private static String value(Value classified, String key) {
    if (classified.state == ValueState.AMBIGUOUS)
      throw new IllegalStateException(
          "Ambiguous transient authority default: " + key + "; reopen the Program and retry");
    return classified.value;
  }

  static boolean containsString(Program program, String list, String key) {
    return string(program, list, key) != null;
  }

  static boolean containsString(Options options, String key) {
    return string(options, key) != null;
  }

  static void setString(Program program, String list, String key, String value) {
    setString(program.getOptions(list), key, value);
  }

  static void setString(Options options, String key, String value) {
    if (value == null) throw new IllegalArgumentException("Null authority value: " + key);
    Value before = classify(options, key);
    value(before, key);
    if (before.defaultValue != null && Objects.equals(before.defaultValue, value))
      throw new IllegalStateException(
          "Authority value equals cached default and cannot be stored safely: "
              + key
              + "; reopen the Program and retry");
    options.setString(key, value);
    if (!Objects.equals(value, string(options, key)))
      throw new IllegalStateException("Authority record was not stored: " + key);
  }

  static void setFamilyString(
      Program program,
      String stockList,
      String stockKey,
      String companionList,
      String companionKey,
      boolean stock,
      String value,
      String description) {
    requireFamilyWrite(
        program,
        stockList,
        stockKey,
        companionList,
        companionKey,
        stock,
        value,
        description);
    String list = stock ? stockList : companionList;
    String key = stock ? stockKey : companionKey;
    setString(program, list, key, value);
    Family after = family(program, stockList, stockKey, companionList, companionKey);
    after.requireCoherent(description);
    if (after.state != (stock ? FamilyState.STOCK : FamilyState.COMPANION)
        || !Objects.equals(value, after.value(description)))
      throw new IllegalStateException("Wrong " + description + " authority after write");
  }

  static void setFamilyString(
      Options options,
      String stockKey,
      String companionKey,
      boolean stock,
      String value,
      String description) {
    requireFamilyWrite(options, stockKey, companionKey, stock, value, description);
    String key = stock ? stockKey : companionKey;
    setString(options, key, value);
    Family after = family(options, stockKey, companionKey);
    after.requireCoherent(description);
    if (after.state != (stock ? FamilyState.STOCK : FamilyState.COMPANION)
        || !Objects.equals(value, after.value(description)))
      throw new IllegalStateException("Wrong " + description + " authority after write");
  }

  static void requireFamilyWrite(
      Program program,
      String stockList,
      String stockKey,
      String companionList,
      String companionKey,
      boolean stock,
      String value,
      String description) {
    Family before = family(program, stockList, stockKey, companionList, companionKey);
    requireCompatible(before, stock, description);
    Options target = program.getOptions(stock ? stockList : companionList);
    requireSafeValue(target, stock ? stockKey : companionKey, value);
  }

  static void requireFamilyWrite(
      Options options,
      String stockKey,
      String companionKey,
      boolean stock,
      String value,
      String description) {
    Family before = family(options, stockKey, companionKey);
    requireCompatible(before, stock, description);
    requireSafeValue(options, stock ? stockKey : companionKey, value);
  }

  private static void requireCompatible(Family before, boolean stock, String description) {
    before.requireCoherent(description);
    if ((stock && before.state == FamilyState.COMPANION)
        || (!stock && before.state == FamilyState.STOCK))
      throw new IllegalArgumentException(
          "Other transport " + description + " authority retained; no implicit conversion");
  }

  private static void requireSafeValue(Options options, String key, String proposed) {
    if (proposed == null) throw new IllegalArgumentException("Null authority value: " + key);
    Value current = classify(options, key);
    value(current, key);
    if (current.defaultValue != null && Objects.equals(current.defaultValue, proposed))
      throw new IllegalStateException(
          "Authority value equals cached default and cannot be stored safely: "
              + key
              + "; reopen the Program and retry");
  }

  static void removeString(Options options, String key) {
    if (classify(options, key).state == ValueState.ABSENT) return;
    requireSafeRemoval(options, key);
    options.removeOption(key);
    if (classify(options, key).state != ValueState.ABSENT)
      throw new IllegalStateException("Authority record was not removed: " + key);
  }

  static void removeFamilyString(
      Program program,
      String stockList,
      String stockKey,
      String companionList,
      String companionKey,
      boolean stock,
      String description) {
    Family before = family(program, stockList, stockKey, companionList, companionKey);
    requireFamilyRemoval(before, stock, description);
    Options target = program.getOptions(stock ? stockList : companionList);
    String targetKey = stock ? stockKey : companionKey;
    requireSafeRemoval(target, targetKey);
    target.removeOption(targetKey);
    Family after = family(program, stockList, stockKey, companionList, companionKey);
    after.requireCoherent(description);
    if (after.state != FamilyState.ABSENT)
      throw new IllegalStateException("Authority record was not removed: " + description);
  }

  static void removeFamilyString(
      Options options,
      String stockKey,
      String companionKey,
      boolean stock,
      String description) {
    Family before = family(options, stockKey, companionKey);
    requireFamilyRemoval(before, stock, description);
    String targetKey = stock ? stockKey : companionKey;
    requireSafeRemoval(options, targetKey);
    options.removeOption(targetKey);
    Family after = family(options, stockKey, companionKey);
    after.requireCoherent(description);
    if (after.state != FamilyState.ABSENT)
      throw new IllegalStateException("Authority record was not removed: " + description);
  }

  static void requireFamilyRemoval(
      Program program,
      String stockList,
      String stockKey,
      String companionList,
      String companionKey,
      boolean stock,
      String description) {
    requireFamilyRemoval(
        family(program, stockList, stockKey, companionList, companionKey), stock, description);
  }

  private static void requireFamilyRemoval(Family before, boolean stock, String description) {
    before.requireCoherent(description);
    FamilyState intended = stock ? FamilyState.STOCK : FamilyState.COMPANION;
    if (before.state != intended)
      throw new IllegalArgumentException("Intended " + description + " authority is not established");
  }

  private static void requireSafeRemoval(Options options, String key) {
    Value before = classify(options, key);
    value(before, key);
    if (before.state != ValueState.PRESENT)
      throw new IllegalArgumentException("Missing authority record for removal: " + key);
    if (before.defaultValue != null)
      throw new IllegalStateException(
          "Authority removal would expose an unprovable cached default: "
              + key
              + "; reopen the Program and retry");
  }
}
