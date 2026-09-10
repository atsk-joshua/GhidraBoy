// @category GhidraBoy.Tests
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import fi.gekkio.ghidraboy.*;
import java.nio.file.*;
import java.util.*;
public class GhidraBoyRuntimeIdentity extends GhidraScript {
  String hash(Path p)throws Exception{return HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(p)));}
  @Override public void run()throws Exception {
    var r=new LinkedHashMap<String,Object>();r.put("pid",ProcessHandle.current().pid());r.put("java",System.getProperty("java.runtime.version"));r.put("java_home",System.getProperty("java.home"));r.put("platform",System.getProperty("os.name")+"/"+System.getProperty("os.arch"));r.put("java_class_path",System.getProperty("java.class.path"));
    var urls=new TreeMap<String,String>();
    for(ClassLoader loader:List.of(ClassLoader.getSystemClassLoader(),getClass().getClassLoader(),Thread.currentThread().getContextClassLoader()))for(ClassLoader at=loader;at!=null;at=at.getParent())if(at instanceof java.net.URLClassLoader u)for(var url:u.getURLs())if(url.getProtocol().equals("file")){var p=Path.of(url.toURI());if(Files.isRegularFile(p)&&p.toString().endsWith(".jar"))urls.put(p.toString(),hash(p));}
    r.put("resolved_classloader_jars",urls);r.put("classloader_inventory_scope","Resolved URL classloader JAR inventory; not instrumentation-based enumeration of loaded classes");
    var origins=new TreeMap<String,String>();for(var c:List.of(Application.class,ghidra.app.decompiler.DecompInterface.class,ghidra.program.model.pcode.PcodeOp.class,StockEntryInjection.class))origins.put(c.getName(),c.getProtectionDomain().getCodeSource().getLocation().toString());r.put("loaded_key_class_origins",origins);
    var nativeFile=Application.getOSFile("decompile").toPath();r.put("resolved_native",nativeFile.toString());r.put("native_sha256",hash(nativeFile));
    var provider=Path.of(StockEntryInjection.class.getProtectionDomain().getCodeSource().getLocation().toURI());r.put("provider_sha256",hash(provider));r.put("language",currentProgram.getLanguageID().toString());r.put("language_version",currentProgram.getLanguage().getVersion());
    Files.writeString(Path.of(getScriptArgs()[0]),ProgramMapping.JSON.toJson(r));println("STOCK_RUNTIME_IDENTITY_COMPLETE");
  }
}
