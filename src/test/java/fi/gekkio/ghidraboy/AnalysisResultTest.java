package fi.gekkio.ghidraboy;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.Test;

class AnalysisResultTest {
  private static final AnalysisResult.OrdinaryCallProof PROOF =
      new AnalysisResult.OrdinaryCallProof(
          "0153", new MapperState.Physical("ROM", 0, 0x153),
          "rom2::4100", new MapperState.Physical("ROM", 2, 0x100),
          "0156", new MapperState.Physical("ROM", 0, 0x156));

  private static AnalysisResult result(int schema, String engine, AnalysisResult.Completion completion) {
    return new AnalysisResult(schema, engine, List.of("0150"), MapperState.reset(), List.of(),
        AnalysisResult.Configuration.DEFAULT, completion, 8, 0, "fixture-fingerprint",
        List.of(), List.of(PROOF), List.of());
  }

  @Test void exactStaticAndPhysicalCertificateIdentitiesSurviveSerialization() {
    var expected = result(AnalysisResult.SCHEMA_VERSION, AnalysisResult.ENGINE_VERSION,
        AnalysisResult.Completion.COMPLETE);
    var restored = AnalysisResult.read(ProgramMapping.JSON.toJson(expected));
    assertEquals(expected, restored);
    assertEquals(List.of(PROOF), restored.ordinaryCallProofs());
    assertThrows(UnsupportedOperationException.class, () -> restored.ordinaryCallProofs().clear());
  }

  @Test void everyIncompleteCompletionSuppressesPositiveObservations() {
    for (var completion : List.of(AnalysisResult.Completion.STATE_LIMIT,
        AnalysisResult.Completion.CANCELLED, AnalysisResult.Completion.INPUT_CHANGED)) {
      var incomplete = result(AnalysisResult.SCHEMA_VERSION, AnalysisResult.ENGINE_VERSION, completion);
      assertTrue(incomplete.ordinaryCallProofs().isEmpty(), completion.toString());
      // Simulate a persisted partial observation supplied directly to Gson rather than read().
      String completeJson = ProgramMapping.JSON.toJson(result(AnalysisResult.SCHEMA_VERSION,
          AnalysisResult.ENGINE_VERSION, AnalysisResult.Completion.COMPLETE));
      var json = completeJson.replace("\"COMPLETE\"", "\"" + completion + "\"");
      assertTrue(ProgramMapping.JSON.fromJson(json, AnalysisResult.class).ordinaryCallProofs().isEmpty());
      assertTrue(AnalysisResult.read(json).ordinaryCallProofs().isEmpty());
    }
  }

  @Test void obsoleteSchemaOrEngineCannotExposeCertificateEvenThroughDirectGson() {
    String current = ProgramMapping.JSON.toJson(result(AnalysisResult.SCHEMA_VERSION,
        AnalysisResult.ENGINE_VERSION, AnalysisResult.Completion.COMPLETE));
    var oldSchema = com.google.gson.JsonParser.parseString(current).getAsJsonObject();
    oldSchema.addProperty("schemaVersion", 3);
    for (String old : List.of(oldSchema.toString(),
        current.replace(AnalysisResult.ENGINE_VERSION, "20260930-n8-finite-pointer-successor-1"))) {
      assertNotEquals(current, old);
      assertThrows(IllegalArgumentException.class, () -> AnalysisResult.read(old));
      assertTrue(ProgramMapping.JSON.fromJson(old, AnalysisResult.class).ordinaryCallProofs().isEmpty());
    }
    assertTrue(result(3, AnalysisResult.ENGINE_VERSION, AnalysisResult.Completion.COMPLETE)
        .ordinaryCallProofs().isEmpty());
    assertTrue(result(4, "obsolete", AnalysisResult.Completion.COMPLETE)
        .ordinaryCallProofs().isEmpty());
  }

  @Test void legacyConstructorsAndMissingProofFieldNeverInferCertificateFromGenericCall() {
    var finding = new BankAnalysis.Finding("0153", "call", List.of("rom2::4100"), null,
        AnalysisResult.Confidence.PROVEN, 0, -1, 0);
    var observations = new AnalysisResult(AnalysisResult.SCHEMA_VERSION, AnalysisResult.ENGINE_VERSION,
        List.of("0150"), MapperState.reset(), List.of(), AnalysisResult.Configuration.DEFAULT,
        AnalysisResult.Completion.COMPLETE, 8, 0, "fixture-fingerprint", List.of(finding), List.of());
    assertTrue(observations.ordinaryCallProofs().isEmpty());
    var preM2 = new AnalysisResult(AnalysisResult.SCHEMA_VERSION, AnalysisResult.ENGINE_VERSION,
        List.of("0150"), MapperState.reset(), AnalysisResult.Configuration.DEFAULT,
        AnalysisResult.Completion.COMPLETE, 8, 0, "fixture-fingerprint", List.of(finding), List.of());
    assertTrue(preM2.ordinaryCallProofs().isEmpty());
    var json = com.google.gson.JsonParser.parseString(ProgramMapping.JSON.toJson(observations)).getAsJsonObject();
    json.remove("ordinaryCallProofs");
    assertTrue(AnalysisResult.read(json.toString()).ordinaryCallProofs().isEmpty());
  }

  @Test void invalidStoredShapesFailWithRepreviewRequirement() {
    for (String json : List.of("null", "[]", "{}", "{\"engineVersion\":null}", "invalid"))
      assertThrows(IllegalArgumentException.class, () -> AnalysisResult.read(json));
  }
}
