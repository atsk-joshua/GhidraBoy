// Read-only, field-rich observation. No enhancement, analysis, repair or proof refresh.
// @category Game Boy Tests
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import java.nio.file.*;
import java.util.*;

public class Sm83PreservationInventory extends GhidraScript {
  static Map<String,Object> row(Object... values) {
    var r=new TreeMap<String,Object>();
    for(int i=0;i<values.length;i+=2) r.put((String)values[i],values[i+1]);
    return r;
  }
  static String addr(Address a) {return a==null?null:a.toString(true);}
  static String hex(byte[] b) {return HexFormat.of().formatHex(b);}
  static List<Object> ranges(AddressSetView s) {
    var r=new ArrayList<Object>(); for(var a:s.getAddressRanges())r.add(List.of(addr(a.getMinAddress()),addr(a.getMaxAddress())));return r;
  }
  static Object storage(Variable v) {
    var nodes=new ArrayList<Object>();for(var n:v.getVariableStorage().getVarnodes())nodes.add(List.of(n.getAddress().getAddressSpace().getName(),n.getOffset(),n.getSize()));
    return row("name",v.getName(),"type",v.getDataType().getPathName(),"length",v.getLength(),"comment",v.getComment(),"source",v.getSource().toString(),"firstUse",v.getFirstUseOffset(),"storage",nodes);
  }
  static Object node(Program p,Varnode n,long uniqueBase,boolean spaceId) {
    if(n==null)return null;
    if(spaceId)return row("spaceId",p.getAddressFactory().getAddressSpace((int)n.getOffset()).getName(),"size",n.getSize());
    return row("space",n.getAddress().getAddressSpace().getName(),"offset",n.isUnique()?n.getOffset()-uniqueBase:n.getOffset(),"size",n.getSize());
  }
  public static Map<String,Object> inventory(Program p) throws Exception {
    var root=new TreeMap<String,Object>();
    root.put("language",row("id",p.getLanguageID().toString(),"version",p.getLanguage().getVersion(),"minor",p.getLanguage().getMinorVersion(),"compiler",p.getCompilerSpec().getCompilerSpecID().toString()));
    var spaces=new ArrayList<Object>();for(var s:p.getAddressFactory().getAllAddressSpaces())spaces.add(row("name",s.getName(),"bits",s.getSize(),"type",s.getType(),"overlay",s.isOverlaySpace(),"physical",s.getPhysicalSpace().getName()));root.put("spaces",spaces);
    var registers=new ArrayList<Object>();for(var r:p.getLanguage().getRegisters())registers.add(row("name",r.getName(),"address",addr(r.getAddress()),"bits",r.getBitLength(),"minimumByteSize",r.getMinimumByteSize(),"lsb",r.getLeastSignificantBit(),"base",r.getBaseRegister().getName(),"context",r.isProcessorContext()));root.put("registers",registers);
    var blocks=new ArrayList<Object>();for(var b:p.getMemory().getBlocks()) {
      var sources=new ArrayList<Object>();for(var s:b.getSourceInfos())sources.add(row("min",addr(s.getMinAddress()),"max",addr(s.getMaxAddress()),"length",s.getLength(),"description",s.getDescription(),"fileOffset",s.getFileBytesOffset(),"file",s.getFileBytes().isPresent()?s.getFileBytes().get().getFilename():null,"mapped",s.getMappedRange().isPresent()?s.getMappedRange().get().toString():null));
      byte[] bytes=b.isInitialized()?new byte[(int)b.getSize()]:null;if(bytes!=null)p.getMemory().getBytes(b.getStart(),bytes);
      blocks.add(row("name",b.getName(),"start",addr(b.getStart()),"end",addr(b.getEnd()),"read",b.isRead(),"write",b.isWrite(),"execute",b.isExecute(),"volatile",b.isVolatile(),"initialized",b.isInitialized(),"type",b.getType().toString(),"comment",b.getComment(),"source",b.getSourceName(),"bytes",bytes==null?null:hex(bytes),"sources",sources));
    }root.put("blocks",blocks);
    var files=new ArrayList<Object>();for(var f:p.getMemory().getAllFileBytes()) {byte[] orig=new byte[(int)f.getSize()],now=orig.clone();f.getOriginalBytes(0,orig);f.getModifiedBytes(0,now);files.add(row("name",f.getFilename(),"offset",f.getFileOffset(),"size",f.getSize(),"original",hex(orig),"modified",hex(now)));}root.put("files",files);
    var instructions=new ArrayList<Object>();for(var it=p.getListing().getInstructions(true);it.hasNext();) {
      var i=it.next();var ops=i.getPcode(false);long base=Long.MAX_VALUE;
      for(var o:ops){if(o.getOutput()!=null&&o.getOutput().isUnique())base=Math.min(base,o.getOutput().getOffset());for(var n:o.getInputs())if(n.isUnique())base=Math.min(base,n.getOffset());}
      var code=new ArrayList<Object>();var raw=new ArrayList<String>();for(var o:ops){var inputs=new ArrayList<Object>();for(int j=0;j<o.getNumInputs();j++)inputs.add(node(p,o.getInput(j),base,j==0&&(o.getOpcode()==PcodeOp.LOAD||o.getOpcode()==PcodeOp.STORE)));code.add(row("op",o.getMnemonic(),"output",node(p,o.getOutput(),base,false),"inputs",inputs));raw.add(o.toString());}
      var flows=new ArrayList<String>();for(var a:i.getFlows())flows.add(addr(a));
      var mode=p.getRegister("gb_analysis_entry");var value=mode==null?null:p.getProgramContext().getValue(mode,i.getAddress(),false);
      instructions.add(row("address",addr(i.getAddress()),"length",i.getLength(),"bytes",hex(i.getBytes()),"display",i.toString(),"mnemonic",i.getMnemonicString(),"flowOverride",i.getFlowOverride().toString(),"fallthroughOverridden",i.isFallThroughOverridden(),"fallthrough",addr(i.getFallThrough()),"flows",flows,"pcode",code,"rawPcode",raw,"analysisMode",value==null?"absent":value.toString()));
    }root.put("instructions",instructions);
    var functions=new ArrayList<Object>();for(var it=p.getFunctionManager().getFunctions(true);it.hasNext();) {
      var f=it.next();var params=new ArrayList<Object>();for(var v:f.getParameters())params.add(storage(v));var locals=new ArrayList<Object>();for(var v:f.getLocalVariables())locals.add(storage(v));
      functions.add(row("entry",addr(f.getEntryPoint()),"name",f.getName(true),"body",ranges(f.getBody()),"signature",f.getSignature().toString(),"signatureSource",f.getSignatureSource().toString(),"convention",f.getCallingConventionName(),"custom",f.hasCustomVariableStorage(),"return",storage(f.getReturn()),"parameters",params,"locals",locals,"thunk",f.isThunk()?addr(f.getThunkedFunction(false).getEntryPoint()):null,"inline",f.isInline(),"noReturn",f.hasNoReturn(),"varargs",f.hasVarArgs(),"purge",f.getStackPurgeSize(),"fixup",f.getCallFixup(),"comment",f.getComment(),"repeatableComment",f.getRepeatableComment()));
    }root.put("functions",functions);
    var symbols=new ArrayList<Object>();for(var it=p.getSymbolTable().getAllSymbols(true);it.hasNext();) {var s=it.next();symbols.add(row("id",s.getID(),"address",addr(s.getAddress()),"name",s.getName(true),"type",s.getSymbolType().toString(),"source",s.getSource().toString(),"primary",s.isPrimary(),"pinned",s.isPinned()));}root.put("symbols",symbols);
    var refs=new ArrayList<Object>();for(var it=p.getReferenceManager().getReferenceSourceIterator(p.getMemory(),true);it.hasNext();)for(var r:p.getReferenceManager().getReferencesFrom(it.next()))refs.add(row("from",addr(r.getFromAddress()),"to",addr(r.getToAddress()),"operand",r.getOperandIndex(),"type",r.getReferenceType().toString(),"source",r.getSource().toString(),"primary",r.isPrimary(),"symbolId",r.getSymbolID()));root.put("references",refs);
    var comments=new ArrayList<Object>();for(int type=0;type<=4;type++)for(var it=p.getListing().getCommentAddressIterator(type,p.getMemory(),true);it.hasNext();) {var a=it.next();comments.add(row("address",addr(a),"type",type,"text",p.getListing().getComment(type,a)));}root.put("comments",comments);
    var bookmarks=new ArrayList<Object>();for(var it=p.getBookmarkManager().getBookmarksIterator();it.hasNext();) {var b=it.next();bookmarks.add(row("address",addr(b.getAddress()),"type",b.getTypeString(),"category",b.getCategory(),"comment",b.getComment()));}root.put("bookmarks",bookmarks);
    var types=new ArrayList<Object>();for(var it=p.getDataTypeManager().getAllDataTypes();it.hasNext();) {var d=it.next();types.add(row("path",d.getPathName(),"length",d.getLength(),"definition",d.toString()));}root.put("types",types);
    var data=new ArrayList<Object>();for(var it=p.getListing().getDefinedData(true);it.hasNext();) {var d=it.next();var settings=new TreeMap<String,Object>();for(var n:d.getNames())settings.put(n,String.valueOf(d.getValue(n)));data.add(row("address",addr(d.getAddress()),"type",d.getDataType().getPathName(),"length",d.getLength(),"settings",settings));}root.put("data",data);
    var facts=new ArrayList<Object>();for(var r:p.getProgramContext().getRegisters())for(var it=p.getProgramContext().getRegisterValueAddressRanges(r);it.hasNext();) {var a=it.next();facts.add(row("register",r.getName(),"start",addr(a.getMinAddress()),"end",addr(a.getMaxAddress()),"value",String.valueOf(p.getProgramContext().getRegisterValue(r,a.getMinAddress()))));}root.put("registerFacts",facts);
    var options=new TreeMap<String,Object>();for(var name:p.getOptionsNames()) {var opt=p.getOptions(name);var values=new TreeMap<String,Object>();for(var n:opt.getOptionNames())values.put(n,row("type",opt.getType(n).toString(),"value",String.valueOf(opt.getObject(n,null))));options.put(name,values);}root.put("options",options);
    return root;
  }
  @Override public void run() throws Exception {
    var args=getScriptArgs();Program p=currentProgram;boolean release=false;
    if(args.length==3) {var f=state.getProject().getProjectData().getRootFolder().getFile(args[2]);p=(Program)(args[0].equals("upgrade")?f.getDomainObject(this,true,false,monitor):f.getImmutableDomainObject(this,-1,monitor));release=true;if(!args[0].equals("upgrade")&&p.isChangeable())throw new AssertionError("Immutable Program required");}
    try {var out=row("phase",args[0],"pid",ProcessHandle.current().pid(),"runtime",ghidra.framework.Application.getApplicationVersion(),"changeable",p.isChangeable(),"state",inventory(p));Files.writeString(Path.of(args[1]),new GsonBuilder().serializeNulls().setPrettyPrinting().create().toJson(out));if(args[0].equals("upgrade"))p.save("Core language translation only",monitor);println("SM83_INVENTORY_PASS "+args[0]);}finally{if(release)p.release(this);}
  }
}
