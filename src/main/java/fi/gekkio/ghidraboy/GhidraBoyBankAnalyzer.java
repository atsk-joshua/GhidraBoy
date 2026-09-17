package fi.gekkio.ghidraboy;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.WeakHashMap;

/** Stock-Ghidra analyzer adapter around the bounded physical bank/state engine. */
public final class GhidraBoyBankAnalyzer extends AbstractAnalyzer {
  public static final String NAME = "GhidraBoy Bank and Mapper Analysis";
  static final String STATE_LIMIT = "Maximum explored states";
  static final String CREATE_FUNCTIONS = "Create functions from proved entries";
  static final int DEFAULT_STATE_LIMIT = 100000;

  private int stateLimit = DEFAULT_STATE_LIMIT;
  private boolean createFunctions = true;
  private final Map<Program, Session> sessions = new WeakHashMap<>();

  private static final class Session {
    final AddressSet restriction = new AddressSet();
    final TreeSet<Address> roots = new TreeSet<>();
  }

  public GhidraBoyBankAnalyzer() {
    super(
        NAME,
        "Runs one bounded, deduplicated physical-bank worklist from justified SM83 code roots.",
        AnalyzerType.INSTRUCTION_ANALYZER);
    setPriority(AnalysisPriority.LOW_PRIORITY);
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis();
  }

  @Override
  public boolean canAnalyze(Program program) {
    return program != null
        && "SM83:LE:16:default".equals(program.getLanguageID().toString());
  }

  @Override
  public boolean getDefaultEnablement(Program program) {
    return canAnalyze(program);
  }

  @Override
  public void registerOptions(Options options, Program program) {
    options.registerOption(
        STATE_LIMIT,
        DEFAULT_STATE_LIMIT,
        null,
        "Maximum number of distinct address/state/value worklist entries for this analyzer run.");
    options.registerOption(
        CREATE_FUNCTIONS,
        true,
        null,
        "Create only missing functions whose entries are independently justified by entry points,"
            + " declared code, or complete proved call results.");
  }

  @Override
  public void optionsChanged(Options options, Program program) {
    int requested = options.getInt(STATE_LIMIT, DEFAULT_STATE_LIMIT);
    stateLimit = Math.max(1, Math.min(100000, requested));
    createFunctions = options.getBoolean(CREATE_FUNCTIONS, true);
  }

  @Override
  public boolean added(
      Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
      throws CancelledException {
    monitor.checkCancelled();
    if (ProgramMapping.cartridge(program) == null) {
      log.appendMsg(NAME, "GhidraBoy legacy preparation is required before bank-aware analysis.");
      return true;
    }
    try {
      var unresolved =
          ProgramMapping.inspect(program).diagnostics().stream()
              .filter(message -> message.startsWith("Legacy RAM identity unresolved:"))
              .toList();
      if (!unresolved.isEmpty()) {
        log.appendMsg(
            NAME,
            "GhidraBoy legacy preparation is required before bank-aware analysis: "
                + String.join(", ", unresolved));
        return true;
      }

      var notifiedRoots = roots(program, set, monitor);
      Session session = sessions.get(program);
      if (session == null && set.getNumAddresses() > 0x10000) {
        session = new Session();
        sessions.put(program, session);
      }
      List<Address> roots = notifiedRoots;
      AddressSetView restriction = set;
      if (session != null) {
        session.restriction.add(set);
        session.roots.addAll(notifiedRoots);
        roots = List.copyOf(session.roots);
        restriction = session.restriction;
      }
      if (roots.isEmpty()) {
        monitor.setMessage("GhidraBoy: no justified instruction roots in the requested range");
        return true;
      }
      monitor.setMessage("GhidraBoy: deriving physical entry state for " + roots.size() + " roots");
      var result =
          BankAnalysis.preview(
              program,
              roots,
              new AnalysisResult.Configuration(stateLimit, false),
              restriction,
              monitor);
      if (result.completion() == AnalysisResult.Completion.CANCELLED) throw new CancelledException();
      if (!result.complete()) {
        log.appendMsg(
            NAME,
            "Bounded analysis stopped with "
                + result.completion()
                + "; no analysis result or confident Program mutation was published.");
        return true;
      }
      monitor.checkCancelled();
      BankAnalysis.apply(program, result, monitor);
      if (createFunctions) {
        monitor.setMessage("GhidraBoy: creating functions from justified entries");
        FunctionDiscovery.discover(program, roots, result, monitor);
      }
      monitor.setMessage(
          "GhidraBoy analysis complete: "
              + result.exploredStates()
              + " states from "
              + roots.size()
              + " roots");
      return true;
    } catch (CancelledException cancelled) {
      throw cancelled;
    } catch (IllegalArgumentException expected) {
      log.appendMsg(NAME, expected.getMessage());
      return true;
    } catch (Exception failure) {
      log.appendException(failure);
      return false;
    }
  }

  @Override
  public void analysisEnded(Program program) {
    sessions.remove(program);
  }

  static List<Address> roots(Program program, AddressSetView set, TaskMonitor monitor)
      throws CancelledException {
    var roots = new TreeSet<Address>();
    var external = program.getSymbolTable().getExternalEntryPointIterator();
    while (external.hasNext()) {
      monitor.checkCancelled();
      var address = external.next();
      if (set.contains(address) && program.getListing().getInstructionAt(address) != null)
        roots.add(address);
    }
    var functions = program.getFunctionManager().getFunctions(set, true);
    while (functions.hasNext()) {
      monitor.checkCancelled();
      var entry = functions.next().getEntryPoint();
      var function = program.getFunctionManager().getFunctionAt(entry);
      if (function != null
          && function.getSymbol().getSource() != SourceType.DEFAULT
          && !AnalysisOwnership.functionOwned(program, entry)
          && program.getListing().getInstructionAt(entry) != null)
        roots.add(entry);
    }
    var ranges = set.getAddressRanges(true);
    boolean localRequest = set.getNumAddresses() <= 0x10000;
    while (ranges.hasNext()) {
      monitor.checkCancelled();
      AddressRange range = ranges.next();
      var instruction = program.getListing().getInstructionAt(range.getMinAddress());
      if (instruction == null) instruction = program.getListing().getInstructionAfter(range.getMinAddress());
      if (instruction != null
          && range.contains(instruction.getAddress())
          && (localRequest
              || program.getFunctionManager().getFunctionContaining(instruction.getAddress()) == null)
          && !AnalysisOwnership.functionOwned(program, instruction.getAddress()))
        roots.add(instruction.getAddress());
    }
    return new ArrayList<>(roots);
  }
}
