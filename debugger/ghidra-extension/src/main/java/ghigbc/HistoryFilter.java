package ghigbc;

import java.util.*;
import ghidra.trace.model.target.TraceObject;

/** Exact physical/epoch/access terms plus literal free-text search. No regular expressions. */
public final class HistoryFilter {
    private static final List<String> REGIONS=List.of("cpu","rom","wram","vram","cart","boot","oam","hram","io","unknown");
    private final Map<String,String> fields=new LinkedHashMap<>();
    private final List<String> text=new ArrayList<>();
    public HistoryFilter(String query) {
        for(String term:query.trim().toLowerCase(Locale.ROOT).split("\\s+")) {
            if(term.isEmpty())continue;int colon=term.indexOf(':');
            if(colon<0){text.add(term);continue;}
            String key=term.substring(0,colon),value=term.substring(colon+1);
            if(!Set.of("region","bank","offset","epoch","access").contains(key)||value.isEmpty())throw new IllegalArgumentException("Use region:, bank:, offset:, epoch:, access: or plain search terms.");
            if(fields.putIfAbsent(key,value)!=null)throw new IllegalArgumentException("Specify "+key+" only once.");
            if(Set.of("bank","offset","epoch").contains(key)){try{if(Long.decode(value)<0)throw new NumberFormatException();}catch(NumberFormatException error){throw new IllegalArgumentException(key+" must be a nonnegative decimal or 0x hexadecimal integer.");}}
            if(key.equals("region")&&!REGIONS.contains(value))throw new IllegalArgumentException("Unknown physical region.");
            if(key.equals("access")&&!Set.of("read","write","execute","unknown").contains(value))throw new IllegalArgumentException("Access must be read, write, execute, or unknown.");
        }
    }
    public boolean matches(TraceObject event,long snap,String displayedText) {
        String haystack=displayedText.toLowerCase(Locale.ROOT);for(String term:text)if(!haystack.contains(term))return false;
        for(var field:fields.entrySet()) {
            String key=field.getKey(),expected=field.getValue();
            Object actual=ObservationReport.value(event,snap,switch(key){case "region"->"TargetRegion";case "bank"->"TargetBank";case "offset"->"TargetOffset";case "epoch"->"Epoch";default->"Access";});
            if(key.equals("region")){int index=actual instanceof Number n?n.intValue():-1;String name=index>=0&&index<REGIONS.size()?REGIONS.get(index):"unknown";if(!expected.equals(name))return false;}
            else if(key.equals("access")){String name=actual instanceof Number n?switch(n.intValue()){case 1->"execute";case 2->"read";case 4->"write";default->"unknown";}:"unknown";if(!expected.equals(name))return false;}
            else if(!(actual instanceof Number n)||n.longValue()!=Long.decode(expected))return false;
        }
        return true;
    }
}
