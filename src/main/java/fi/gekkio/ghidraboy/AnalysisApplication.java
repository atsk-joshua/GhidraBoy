package fi.gekkio.ghidraboy;

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import java.util.*;
import fi.gekkio.ghidraboy.BankAnalysis.Finding;

/** Applies versioned, current results in a single transaction and records ownership. */
final class AnalysisApplication {
    private AnalysisApplication() { }
    private record OwnedReference(String from,String to,String type) { }
    public static void apply(Program p,AnalysisResult result,TaskMonitor monitor) throws Exception {
        ProgramFingerprint.requireCurrent(p,result,monitor);
        if(result.completion()==AnalysisResult.Completion.CANCELLED) throw new ghidra.util.exception.CancelledException();
        var findings=result.findings();
            int tx=p.startTransaction("GhidraBoy bank analysis"); boolean success=false;
            try {
                var options=p.getOptions(ProgramMapping.OPTIONS);
                var prior=com.google.gson.JsonParser.parseString(options.getString("analysis.latest","null"));
                var priorFindings=prior.isJsonArray()?prior:prior.isJsonObject()?prior.getAsJsonObject().get("findings"):null;
                if(priorFindings!=null && priorFindings.isJsonArray()) {
                    var last=new LinkedHashMap<String,Finding>();
                    for(var finding:ProgramMapping.JSON.fromJson(priorFindings,Finding[].class)) last.put(finding.source(),finding);
                    for(var finding:last.values()) {
                        var address=p.getAddressFactory().getAddress(finding.source());
                        var bookmark=address==null?null:p.getBookmarkManager().getBookmark(address,"Analysis","GhidraBoy");
                        if(bookmark!=null && bookmark.getComment().equals(finding.access()+": "+finding.reason()+" "+finding.targets()))
                            p.getBookmarkManager().removeBookmark(bookmark);
                    }
                }
                var old=ProgramMapping.JSON.fromJson(options.getString("analysis.ownedReferences","[]"),OwnedReference[].class);
                for(var owned:old) {
                    var from=p.getAddressFactory().getAddress(owned.from);
                    if(from==null) continue;
                    for(var ref:p.getReferenceManager().getReferencesFrom(from))
                        if(ref.getOperandIndex()==-1 && ref.getSource()==SourceType.ANALYSIS && ref.getToAddress().toString().equals(owned.to)
                            && ref.getReferenceType().toString().equals(owned.type)) p.getReferenceManager().delete(ref);
                }
                AnalysisOwnership.remove(p,"bank-analysis",monitor);
                var owned=new AnalysisOwnership.Group();
                var introduced=new ArrayList<OwnedReference>();
                for(var f:findings) {
                    monitor.checkCancelled(); var source=p.getAddressFactory().getAddress(f.source());
                    if(source==null) continue;
                    // References are supplemental; never replace existing operand/user references.
                    if(result.complete() && f.confidence()==AnalysisResult.Confidence.PROVEN && f.targets().size()==1) {
                        var dest=p.getAddressFactory().getAddress(f.targets().get(0));
                        boolean exists=false;
                        for(var ref:p.getReferenceManager().getReferencesFrom(source)) if(ref.getToAddress().equals(dest)) exists=true;
                        // A mnemonic-level non-memory reference would be removed by Ghidra's API; preserve it.
                        for(var ref:p.getReferenceManager().getReferencesFrom(source)) if(ref.getOperandIndex()==-1 && !ref.isMemoryReference()) exists=true;
                        if(!exists) {
                            var added=p.getReferenceManager().addMemoryReference(source,dest,
                            f.access().equals("write")?RefType.WRITE:f.access().equals("read")?RefType.READ:RefType.DATA,SourceType.ANALYSIS,-1);
                            owned.reference(added);
                        }
                    }
                    String category="GhidraBoy Bank Analysis " + f.access();
                    if(p.getBookmarkManager().getBookmark(source,"Analysis",category)==null)
                        owned.bookmark(p.getBookmarkManager().setBookmark(source,"Analysis",category,f.confidence()+": "+f.reason()+" "+f.targets()));
                }
                options.removeOption("analysis.ownedReferences");
                AnalysisOwnership.save(p,"bank-analysis",owned);
                options.setString("analysis.latest",ProgramMapping.JSON.toJson(result));
                success=true;
            } finally { p.endTransaction(tx,success); }
    }
}
