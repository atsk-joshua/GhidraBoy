package fi.gekkio.ghidraboy;

import static org.junit.jupiter.api.Assertions.*;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.data.OpenMode;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Persisted authority must not be inferred from Ghidra's transient typed Options cache. */
final class AuthorityMembershipTest extends IntegrationTest {
  @TempDir java.nio.file.Path temporary;

  @FunctionalInterface
  private interface Action {
    void run(ProgramDB program, Function source) throws Exception;
  }

  private void fixture(Action action) throws Exception {
    var owner = new Object();
    var program =
        new ProgramDB(
            "authority-membership", language, language.getDefaultCompilerSpec(), owner);
    try {
      byte[] bytes =
          getClass().getResourceAsStream("/ordinary/PREDICATED_CALLS.gb").readAllBytes();
      try (var provider = new ByteArrayProvider(bytes)) {
        CartridgeLayout.load(
            program,
            provider,
            "CARTRIDGE",
            "AUTO",
            GameBoyKind.GB,
            false,
            false,
            TaskMonitor.DUMMY,
            new MessageLog());
      }
      int transaction = program.startTransaction("self-authored authority fixture");
      Function source;
      try {
        var body = new AddressSet(address(0x150), address(0x164));
        Disassembler.getDisassembler(program, TaskMonitor.DUMMY, null)
            .disassemble(address(0x150), body);
        source =
            program
                .getFunctionManager()
                .createFunction("source", address(0x150), body, SourceType.USER_DEFINED);
      } finally {
        program.endTransaction(transaction, true);
      }
      action.run(program, source);
    } finally {
      program.release(owner);
    }
  }

  private void ordinaryFixture(Action action) throws Exception {
    var owner = new Object();
    var program =
        new ProgramDB(
            "authority-ordinary", language, language.getDefaultCompilerSpec(), owner);
    try {
      byte[] bytes = new byte[0x10000];
      bytes[0x147] = 0x19;
      bytes[0x148] = 1;
      bytes[0x2000] = 0x6e;
      bytes[0x6000] = 0x31;
      bytes[0xa000] = (byte) 0xa7;
      bytes[0xe000] = (byte) 0xd3;
      byte[] instructions =
          java.util.HexFormat.of()
              .parseHex("3e01ea00202100607eea00c03e02ea00207eea01c0fa0020ea02c0c9");
      System.arraycopy(instructions, 0, bytes, 0x150, instructions.length);
      try (var provider = new ByteArrayProvider(bytes)) {
        CartridgeLayout.load(
            program,
            provider,
            "CARTRIDGE",
            "AUTO",
            GameBoyKind.GB,
            false,
            false,
            TaskMonitor.DUMMY,
            new MessageLog());
      }
      int transaction = program.startTransaction("self-authored ordinary authority fixture");
      Function source;
      try {
        var body = new AddressSet(address(0x150), address(0x150 + instructions.length - 1L));
        Disassembler.getDisassembler(program, TaskMonitor.DUMMY, null)
            .disassemble(address(0x150), body);
        source =
            program
                .getFunctionManager()
                .createFunction("source", address(0x150), body, SourceType.USER_DEFINED);
      } finally {
        program.endTransaction(transaction, true);
      }
      action.run(program, source);
    } finally {
      program.release(owner);
    }
  }

  private static String companionRecord(String stockRecord, String companionVersion) {
    var json = com.google.gson.JsonParser.parseString(stockRecord).getAsJsonObject();
    json.addProperty("version", companionVersion);
    json.add("transport", com.google.gson.JsonNull.INSTANCE);
    json.add("nativeIdentity", com.google.gson.JsonNull.INSTANCE);
    return json.toString();
  }

  @Test
  void typedMissingReadsCannotCreateExecutableAuthority() throws Exception {
    fixture(
        (program, source) -> {
          var proof =
              PredicatedCalls.preview(
                  program, source, PredicatedCallGraph.Limits.PRIMARY, TaskMonitor.DUMMY);
          var carrier = PredicatedCalls.installStock(program, proof, TaskMonitor.DUMMY);
          var stockOptions = program.getOptions(PredicatedCalls.STOCK_OPTIONS);
          String validRecord = stockOptions.getString(carrier.toString(), null);
          assertNotNull(validRecord);
          assertTrue(PredicatedCalls.registered(program, carrier));
          assertTrue(StockEntryInjection.owned(program, carrier));

          Address nullDefault = source.getEntryPoint();
          Address nonNullDefault = nullDefault.add(1);
          long revision = program.getModificationNumber();

          assertNull(stockOptions.getString(nullDefault.toString(), null));
          assertEquals(
              validRecord, stockOptions.getString(nonNullDefault.toString(), validRecord));
          assertTrue(stockOptions.contains(nullDefault.toString()));
          assertTrue(stockOptions.contains(nonNullDefault.toString()));

          // This is the old qualified-source membership rule and the W2 false positive.
          assertTrue(
              stockOptions.contains(nullDefault.toString())
                  || stockOptions.contains(nonNullDefault.toString()));
          assertEquals(revision, program.getModificationNumber());

          assertFalse(StockEntryInjection.owned(program, nullDefault));
          assertThrows(
              IllegalStateException.class,
              () -> StockEntryInjection.owned(program, nonNullDefault));
          assertFalse(PredicatedCalls.registered(program, nullDefault));
          assertThrows(
              IllegalStateException.class,
              () -> PredicatedCalls.registered(program, nonNullDefault));

          var ordinaryStock = program.getOptions(OrdinaryEntryAccess.STOCK_OPTIONS);
          var ordinaryCompanion = program.getOptions(OrdinaryEntryAccess.OPTIONS);
          assertNull(ordinaryStock.getString(nullDefault.toString(), null));
          assertEquals(
              validRecord,
              ordinaryCompanion.getString(nonNullDefault.toString(), validRecord));
          assertFalse(OrdinaryEntryAccess.registered(program, nullDefault));
          assertThrows(
              IllegalStateException.class,
              () -> OrdinaryEntryAccess.registered(program, nonNullDefault));

          assertNull(
              program
                  .getOptions(SoftwareCallDomains.STOCK_OPTIONS)
                  .getString("registration", null));
          assertFalse(SoftwareCallDomains.registered(program, nullDefault));
          assertEquals(
              validRecord,
              program
                  .getOptions(SoftwareCallDomains.OPTIONS)
                  .getString("registration", validRecord));
          assertThrows(
              IllegalStateException.class,
              () -> SoftwareCallDomains.registered(program, nullDefault));

          var common = program.getOptions(ProgramMapping.OPTIONS);
          assertNull(common.getString(SoftwareCallRegistry.STOCK_KEY, null));
          assertNull(AuthorityOptions.string(common, SoftwareCallRegistry.STOCK_KEY));
          assertFalse(SoftwareCallRegistry.stock(program));
          assertEquals("absent", SoftwareCallRegistry.configurationIdentity(program));
          assertEquals(
              validRecord, common.getString(SoftwareCallRegistry.KEY, validRecord));
          assertThrows(
              IllegalStateException.class,
              () -> AuthorityOptions.string(common, SoftwareCallRegistry.KEY));
          assertThrows(IllegalStateException.class, () -> SoftwareCallRegistry.stock(program));
          assertThrows(
              IllegalStateException.class,
              () -> SoftwareCallRegistry.configurationIdentity(program));

          String emptyOwnership = "{\"version\":5,\"groups\":{}}";
          assertEquals(
              emptyOwnership, common.getString("analysis.ownership.v1", emptyOwnership));
          assertThrows(
              IllegalStateException.class,
              () -> AuthorityOptions.string(common, "analysis.ownership.v1"));
          assertFalse(AnalysisOwnership.softwareCallCurrent(program, nullDefault));

          String emptyImages =
              "{\"version\":\"executable-images-1\",\"programId\":"
                  + program.getUniqueProgramID()
                  + ",\"sequence\":0,\"history\":[],\"current\":{}}";
          assertEquals(
              emptyImages,
              program
                  .getOptions(ExecutableImages.OPTIONS)
                  .getString("authority", emptyImages));
          assertThrows(IllegalStateException.class, () -> ExecutableImages.serialized(program));
          assertThrows(IllegalStateException.class, () -> ExecutableImages.history(program));

          assertEquals(revision, program.getModificationNumber());
          assertTrue(PredicatedCalls.registered(program, carrier));
          assertTrue(StockEntryInjection.owned(program, carrier));
        });
  }

  @Test
  void genuineStockAuthoritySurvivesPackedReopen() throws Exception {
    fixture(
        (program, source) -> {
          var carrier =
              PredicatedCalls.installStock(
                  program,
                  PredicatedCalls.preview(
                      program, source, PredicatedCallGraph.Limits.PRIMARY, TaskMonitor.DUMMY),
                  TaskMonitor.DUMMY);
          String savedRecord =
              program
                  .getOptions(PredicatedCalls.STOCK_OPTIONS)
                  .getString(carrier.toString(), null);
          int registryTransaction=program.startTransaction("saved stock registry authority");
          try {
            SoftwareCallRegistry.install(program,java.util.List.of());
          } finally {
            program.endTransaction(registryTransaction,true);
          }
          String savedRegistry=program.getOptions(ProgramMapping.OPTIONS).getString(SoftwareCallRegistry.STOCK_KEY,null);
          int ownershipTransaction=program.startTransaction("saved ownership authority");
          try {
            AnalysisOwnership.save(program,"preserved",new AnalysisOwnership.Group());
          } finally {
            program.endTransaction(ownershipTransaction,true);
          }
          String savedOwnership=program.getOptions(ProgramMapping.OPTIONS).getString("analysis.ownership.v1",null);
          var packedFile = temporary.resolve("authority-reopen.gzf").toFile();
          program.saveToPackedFile(packedFile, TaskMonitor.DUMMY);
          var database = PackedDatabase.getPackedDatabase(packedFile, true, TaskMonitor.DUMMY);
          var consumer = new Object();
          ProgramDB reopened = null;
          try {
            reopened =
                new ProgramDB(
                    database.open(TaskMonitor.DUMMY),
                    OpenMode.IMMUTABLE,
                    TaskMonitor.DUMMY,
                    consumer);
            var reopenedCarrier = reopened.getAddressFactory().getAddress(carrier.toString());
            assertEquals(
                savedRecord,
                reopened
                    .getOptions(PredicatedCalls.STOCK_OPTIONS)
                    .getString(reopenedCarrier.toString(), "untrusted-observer-default"));
            assertTrue(PredicatedCalls.registered(reopened, reopenedCarrier));
            assertTrue(StockEntryInjection.owned(reopened, reopenedCarrier));
            assertTrue(SoftwareCallRegistry.stock(reopened));
            assertEquals(
                PredicatedCalls.registeredProof(program, carrier),
                PredicatedCalls.registeredProof(reopened, reopenedCarrier));
          } finally {
            if (reopened != null) reopened.release(consumer);
            database.dispose();
          }

          var equalDatabase =
              PackedDatabase.getPackedDatabase(packedFile, true, TaskMonitor.DUMMY);
          var equalConsumer = new Object();
          ProgramDB equalDefault = null;
          try {
            equalDefault =
                new ProgramDB(
                    equalDatabase.openForUpdate(TaskMonitor.DUMMY),
                    OpenMode.UPDATE,
                    TaskMonitor.DUMMY,
                    equalConsumer);
            var reopenedCarrier =
                equalDefault.getAddressFactory().getAddress(carrier.toString());
            assertEquals(
                savedRecord,
                equalDefault
                    .getOptions(PredicatedCalls.STOCK_OPTIONS)
                    .getString(reopenedCarrier.toString(), savedRecord));
            ProgramDB observed=equalDefault;
            // Public Options APIs cannot distinguish this exact-equal default from an absent
            // transient value, so executable authority refuses rather than guessing.
            assertThrows(
                IllegalStateException.class,
                () ->
                    AuthorityOptions.string(
                        observed,
                        PredicatedCalls.STOCK_OPTIONS,
                        reopenedCarrier.toString()));
            assertThrows(
                IllegalStateException.class,
                () -> PredicatedCalls.registered(observed, reopenedCarrier));
            assertThrows(
                IllegalStateException.class,
                () -> StockEntries.current(observed, reopenedCarrier, TaskMonitor.DUMMY));
            var ownership=equalDefault.getOptions(ProgramMapping.OPTIONS);
            assertEquals(savedOwnership,ownership.getString("analysis.ownership.v1",savedOwnership));
            int attempted=equalDefault.startTransaction("preserve hidden saved authority");
            try {
              var failure=assertThrows(IllegalStateException.class,()->AnalysisOwnership.save(observed,"replacement",new AnalysisOwnership.Group()));
              assertTrue(failure.getMessage().contains("Ambiguous transient authority default"));
            } finally {
              equalDefault.endTransaction(attempted,false);
            }
            assertEquals(savedOwnership,ownership.getString("analysis.ownership.v1",null));

          } finally {
            if (equalDefault != null) equalDefault.release(equalConsumer);
            equalDatabase.dispose();
          }

          var recoveryDatabase =
              PackedDatabase.getPackedDatabase(packedFile, true, TaskMonitor.DUMMY);
          var recoveryConsumer = new Object();
          ProgramDB recovered = null;
          try {
            recovered =
                new ProgramDB(
                    recoveryDatabase.open(TaskMonitor.DUMMY),
                    OpenMode.IMMUTABLE,
                    TaskMonitor.DUMMY,
                    recoveryConsumer);
            var recoveredCarrier = recovered.getAddressFactory().getAddress(carrier.toString());
            assertTrue(PredicatedCalls.registered(recovered, recoveredCarrier));
            assertEquals(savedRecord, AuthorityOptions.string(recovered, PredicatedCalls.STOCK_OPTIONS,
                recoveredCarrier.toString()));
          } finally {
            if (recovered != null) recovered.release(recoveryConsumer);
            recoveryDatabase.dispose();
          }

          var registryDatabase =
              PackedDatabase.getPackedDatabase(packedFile, true, TaskMonitor.DUMMY);
          var registryConsumer = new Object();
          ProgramDB hiddenRegistry = null;
          try {
            hiddenRegistry =
                new ProgramDB(
                    registryDatabase.openForUpdate(TaskMonitor.DUMMY),
                    OpenMode.UPDATE,
                    TaskMonitor.DUMMY,
                    registryConsumer);
            var options=hiddenRegistry.getOptions(ProgramMapping.OPTIONS);
            assertEquals(
                savedRegistry,
                options.getString(SoftwareCallRegistry.STOCK_KEY,savedRegistry));
            ProgramDB observed=hiddenRegistry;
            int conflicting=hiddenRegistry.startTransaction("refuse hidden opposite transport");
            try {
              assertThrows(
                  IllegalStateException.class,
                  () ->
                      SoftwareCallRegistry.install(
                          observed,
                          java.util.List.of(),
                          java.util.Map.of(),
                          java.util.Set.of(),
                          java.util.Map.of(),
                          false));
              assertThrows(
                  IllegalStateException.class,
                  () -> SoftwareCallRegistry.remove(observed));
            } finally {
              hiddenRegistry.endTransaction(conflicting,false);
            }
            assertFalse(options.contains(SoftwareCallRegistry.KEY));
            assertEquals(
                savedRegistry,options.getString(SoftwareCallRegistry.STOCK_KEY,null));
          } finally {
            if(hiddenRegistry!=null)hiddenRegistry.release(registryConsumer);
            registryDatabase.dispose();
          }
        });
  }

  @Test
  void predicatedFamiliesRefuseOppositeAmbiguityInBothOrientations() throws Exception {
    fixture(
        (program, source) -> {
          var entry =
              PredicatedCalls.installStock(
                  program,
                  PredicatedCalls.preview(
                      program, source, PredicatedCallGraph.Limits.PRIMARY, TaskMonitor.DUMMY),
                  TaskMonitor.DUMMY);
          String key = entry.toString();
          String stock = program.getOptions(PredicatedCalls.STOCK_OPTIONS).getString(key, null);
          assertNotNull(stock);
          assertTrue(PredicatedCalls.registered(program, entry));
          assertNotNull(PredicatedCalls.registeredProof(program, entry));
          assertEquals(stock,
              program.getOptions(PredicatedCalls.OPTIONS).getString(key, stock));
          assertThrows(IllegalStateException.class,
              () -> PredicatedCalls.registered(program, entry));
          assertThrows(IllegalStateException.class,
              () -> PredicatedCalls.registeredProof(program, entry));
          assertThrows(IllegalStateException.class,
              () -> StockEntryInjection.owned(program, entry));
        });

    fixture(
        (program, source) -> {
          var entry =
              PredicatedCalls.installStock(
                  program,
                  PredicatedCalls.preview(
                      program, source, PredicatedCallGraph.Limits.PRIMARY, TaskMonitor.DUMMY),
                  TaskMonitor.DUMMY);
          String key = entry.toString();
          var stockOptions = program.getOptions(PredicatedCalls.STOCK_OPTIONS);
          var companionOptions = program.getOptions(PredicatedCalls.OPTIONS);
          String stock = stockOptions.getString(key, null);
          String companion = companionRecord(stock, PredicatedCalls.VERSION);
          int convert = program.startTransaction("test persisted companion authority");
          try {
            stockOptions.removeOption(key);
            companionOptions.setString(key, companion);
          } finally {
            program.endTransaction(convert, true);
          }
          assertTrue(PredicatedCalls.registered(program, entry));
          assertNotNull(PredicatedCalls.registeredProof(program, entry));
          assertEquals(companion, stockOptions.getString(key, companion));
          assertThrows(IllegalStateException.class,
              () -> PredicatedCalls.registered(program, entry));
          assertThrows(IllegalStateException.class,
              () -> PredicatedCalls.registeredProof(program, entry));
          assertThrows(IllegalStateException.class,
              () -> StockEntryInjection.owned(program, entry));
        });
  }

  @Test
  void ordinaryFamiliesRefuseOppositeAmbiguityInBothOrientations() throws Exception {
    ordinaryFixture(
        (program, source) -> {
          var entry = OrdinaryEntryAccess.installStock(
              program, OrdinaryEntryAccess.preview(program, source, TaskMonitor.DUMMY),
              TaskMonitor.DUMMY);
          String key = entry.toString();
          String stock = program.getOptions(OrdinaryEntryAccess.STOCK_OPTIONS).getString(key, null);
          assertTrue(OrdinaryEntryAccess.registered(program, entry));
          assertNotNull(OrdinaryEntryAccess.registeredProof(program, entry));
          assertEquals(stock,
              program.getOptions(OrdinaryEntryAccess.OPTIONS).getString(key, stock));
          assertThrows(IllegalStateException.class,
              () -> OrdinaryEntryAccess.registered(program, entry));
          assertThrows(IllegalStateException.class,
              () -> OrdinaryEntryAccess.registeredProof(program, entry));
          assertThrows(IllegalStateException.class,
              () -> StockEntryInjection.owned(program, entry));
        });

    ordinaryFixture(
        (program, source) -> {
          var entry = OrdinaryEntryAccess.installStock(
              program, OrdinaryEntryAccess.preview(program, source, TaskMonitor.DUMMY),
              TaskMonitor.DUMMY);
          String key = entry.toString();
          var stockOptions = program.getOptions(OrdinaryEntryAccess.STOCK_OPTIONS);
          var companionOptions = program.getOptions(OrdinaryEntryAccess.OPTIONS);
          String stock = stockOptions.getString(key, null);
          String companion = companionRecord(stock, OrdinaryEntryAccess.VERSION);
          int convert = program.startTransaction("test persisted ordinary companion authority");
          try {
            stockOptions.removeOption(key);
            companionOptions.setString(key, companion);
          } finally {
            program.endTransaction(convert, true);
          }
          assertTrue(OrdinaryEntryAccess.registered(program, entry));
          assertNotNull(OrdinaryEntryAccess.registeredProof(program, entry));
          assertEquals(companion, stockOptions.getString(key, companion));
          assertThrows(IllegalStateException.class,
              () -> OrdinaryEntryAccess.registered(program, entry));
          assertThrows(IllegalStateException.class,
              () -> OrdinaryEntryAccess.registeredProof(program, entry));
          assertThrows(IllegalStateException.class,
              () -> StockEntryInjection.owned(program, entry));
        });
  }

  @Test
  void softwareRegistryFamiliesRefuseOppositeAmbiguityInBothOrientations() throws Exception {
    fixture(
        (program, source) -> {
          int install = program.startTransaction("install stock registry");
          try {
            SoftwareCallRegistry.install(program, java.util.List.of());
          } finally {
            program.endTransaction(install, true);
          }
          var options = program.getOptions(ProgramMapping.OPTIONS);
          String stock = options.getString(SoftwareCallRegistry.STOCK_KEY, null);
          assertTrue(SoftwareCallRegistry.stock(program));
          assertNotEquals("absent", SoftwareCallRegistry.configurationIdentity(program));
          assertEquals(stock, options.getString(SoftwareCallRegistry.KEY, stock));
          assertThrows(IllegalStateException.class, () -> SoftwareCallRegistry.stock(program));
          assertThrows(IllegalStateException.class,
              () -> SoftwareCallRegistry.configurationIdentity(program));
          assertThrows(IllegalStateException.class,
              () -> SoftwareCallRegistry.requireStockPreview(program));
        });

    fixture(
        (program, source) -> {
          int install = program.startTransaction("install stock registry control");
          try {
            SoftwareCallRegistry.install(program, java.util.List.of());
          } finally {
            program.endTransaction(install, true);
          }
          var options = program.getOptions(ProgramMapping.OPTIONS);
          String stock = options.getString(SoftwareCallRegistry.STOCK_KEY, null);
          String companion = companionRecord(stock, SoftwareCallRegistry.VERSION);
          int convert = program.startTransaction("test persisted companion registry");
          try {
            options.removeOption(SoftwareCallRegistry.STOCK_KEY);
            options.setString(SoftwareCallRegistry.KEY, companion);
          } finally {
            program.endTransaction(convert, true);
          }
          assertFalse(SoftwareCallRegistry.stock(program));
          assertNotEquals("absent", SoftwareCallRegistry.configurationIdentity(program));
          assertEquals(companion,
              options.getString(SoftwareCallRegistry.STOCK_KEY, companion));
          assertThrows(IllegalStateException.class, () -> SoftwareCallRegistry.stock(program));
          assertThrows(IllegalStateException.class,
              () -> SoftwareCallRegistry.configurationIdentity(program));
          assertThrows(IllegalStateException.class,
              () -> SoftwareCallRegistry.requireStockPreview(program));
        });
  }

  @Test
  void refusedExactDefaultWriteCannotDeletePersistedAuthorityWhenCallerCommits() throws Exception {
    fixture(
        (program, source) -> {
          var options = program.getOptions(ProgramMapping.OPTIONS);
          String key = "authority.case-m";
          String removalKey = "authority.removal-safety";
          String negativeKey = "authority.old-negative-control";
          String persisted = "persisted-Y";
          String cachedDefault = "requested-X";
          int first = program.startTransaction("create case-M authority");
          try {
            AuthorityOptions.setString(options, key, persisted);
            AuthorityOptions.setString(options, removalKey, persisted);
            AuthorityOptions.setString(options, negativeKey, persisted);
          } finally {
            program.endTransaction(first, true);
          }
          var persistedFile = temporary.resolve("case-m-persisted.gzf").toFile();
          program.saveToPackedFile(persistedFile, TaskMonitor.DUMMY);
          var database = PackedDatabase.getPackedDatabase(persistedFile, true, TaskMonitor.DUMMY);
          var consumer = new Object();
          ProgramDB reopened = null;
          try {
            reopened =
                new ProgramDB(
                    database.openForUpdate(TaskMonitor.DUMMY),
                    OpenMode.UPDATE,
                    TaskMonitor.DUMMY,
                    consumer);
            var reopenedOptions = reopened.getOptions(ProgramMapping.OPTIONS);
            assertEquals(persisted, reopenedOptions.getString(key, cachedDefault));
            assertEquals(persisted, reopenedOptions.getString(removalKey, cachedDefault));
            assertEquals(persisted, reopenedOptions.getString(negativeKey, cachedDefault));
            assertThrows(IllegalArgumentException.class,
                () -> AuthorityOptions.setString(reopenedOptions, key, null));
            assertEquals(persisted, reopenedOptions.getString(key, null));

            ProgramDB observed = reopened;
            int attempted = reopened.startTransaction("case-M caller-managed outer transaction");
            try {
              var failure =
                  assertThrows(
                      IllegalStateException.class,
                      () -> AuthorityOptions.setString(
                          observed.getOptions(ProgramMapping.OPTIONS), key, cachedDefault));
              assertTrue(failure.getMessage().contains("equals cached default"));
            } finally {
              // The caller catches the refusal and commits anyway. Safety must not depend on rollback.
              reopened.endTransaction(attempted, true);
            }
            assertEquals(persisted, reopenedOptions.getString(key, null));
            assertEquals(persisted, AuthorityOptions.string(reopenedOptions, key));

            int refusedRemoval = reopened.startTransaction("refused cached-default removal");
            try {
              assertThrows(IllegalStateException.class,
                  () -> AuthorityOptions.removeString(reopenedOptions, removalKey));
            } finally {
              reopened.endTransaction(refusedRemoval, true);
            }
            assertEquals(persisted, reopenedOptions.getString(removalKey, null));

            // Independently express the rejected AUTH-R1 order: mutate, then verify. Ghidra removes
            // the persisted row because X equals the cached default, and a caught refusal commits it.
            int negative = reopened.startTransaction("old mutate-then-verify negative control");
            try {
              reopenedOptions.setString(negativeKey, cachedDefault);
              assertThrows(IllegalStateException.class,
                  () -> AuthorityOptions.string(reopenedOptions, negativeKey));
            } finally {
              reopened.endTransaction(negative, true);
            }
            assertThrows(IllegalStateException.class,
                () -> AuthorityOptions.string(reopenedOptions, negativeKey));

            var afterFile = temporary.resolve("case-m-after-commit.gzf").toFile();
            reopened.saveToPackedFile(afterFile, TaskMonitor.DUMMY);
            var afterDatabase = PackedDatabase.getPackedDatabase(afterFile, true, TaskMonitor.DUMMY);
            var afterConsumer = new Object();
            ProgramDB after = null;
            try {
              after = new ProgramDB(afterDatabase.open(TaskMonitor.DUMMY), OpenMode.IMMUTABLE,
                  TaskMonitor.DUMMY, afterConsumer);
              assertEquals(persisted,
                  AuthorityOptions.string(after, ProgramMapping.OPTIONS, key));
              assertEquals(persisted,
                  AuthorityOptions.string(after, ProgramMapping.OPTIONS, removalKey));
              assertNull(AuthorityOptions.string(after, ProgramMapping.OPTIONS, negativeKey));
            } finally {
              if (after != null) after.release(afterConsumer);
              afterDatabase.dispose();
            }
          } finally {
            if (reopened != null) reopened.release(consumer);
            database.dispose();
          }
        });
  }

  @Test
  void genuineRegistryRemovalPersistsAcrossReopen() throws Exception {
    fixture(
        (program, source) -> {
          int install = program.startTransaction("install removable authority");
          try {
            SoftwareCallRegistry.install(program, java.util.List.of());
          } finally {
            program.endTransaction(install, true);
          }
          assertTrue(SoftwareCallRegistry.stock(program));
          int remove = program.startTransaction("remove genuine authority");
          try {
            SoftwareCallRegistry.remove(program);
          } finally {
            program.endTransaction(remove, true);
          }
          assertEquals("absent", SoftwareCallRegistry.configurationIdentity(program));

          var packedFile = temporary.resolve("removed-authority-reopen.gzf").toFile();
          program.saveToPackedFile(packedFile, TaskMonitor.DUMMY);
          var database = PackedDatabase.getPackedDatabase(packedFile, true, TaskMonitor.DUMMY);
          var consumer = new Object();
          ProgramDB reopened = null;
          try {
            reopened =
                new ProgramDB(
                    database.open(TaskMonitor.DUMMY),
                    OpenMode.IMMUTABLE,
                    TaskMonitor.DUMMY,
                    consumer);
            assertFalse(reopened.getOptions(ProgramMapping.OPTIONS)
                .contains(SoftwareCallRegistry.STOCK_KEY));
            assertFalse(reopened.getOptions(ProgramMapping.OPTIONS)
                .contains(SoftwareCallRegistry.KEY));
            assertEquals("absent", SoftwareCallRegistry.configurationIdentity(reopened));
          } finally {
            if (reopened != null) reopened.release(consumer);
            database.dispose();
          }
        });
  }
}
