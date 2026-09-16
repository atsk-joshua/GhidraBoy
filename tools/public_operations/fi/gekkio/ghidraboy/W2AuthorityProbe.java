package fi.gekkio.ghidraboy;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import java.util.LinkedHashMap;
import java.util.Map;

/** Read-only W2 support bridge to the production authority classifier. */
public final class W2AuthorityProbe {
  private W2AuthorityProbe() {}

  public static String predicatedStockRecord(Program program, Address entry) {
    return PredicatedCalls.stockRecord(program, entry);
  }

  public static Map<String, Object> observe(Program program, Address entry) {
    var result = new LinkedHashMap<String, Object>();
    result.put("stock_entry_owned", StockEntryInjection.owned(program, entry));
    result.put("predicated_registered", PredicatedCalls.registered(program, entry));
    result.put("predicated_stock_registered", PredicatedCalls.stockRegistered(program, entry));
    result.put("predicated_companion_registered", PredicatedCalls.companionRegistered(program, entry));
    result.put("ordinary_registered", OrdinaryEntryAccess.registered(program, entry));
    result.put("ordinary_stock_registered", OrdinaryEntryAccess.stockRegistered(program, entry));
    result.put("ordinary_companion_registered", OrdinaryEntryAccess.companionRegistered(program, entry));
    return Map.copyOf(result);
  }
}
