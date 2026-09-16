import com.sun.jdi.*;
import com.sun.jdi.connect.*;
import com.sun.jdi.event.*;
import com.sun.jdi.request.*;
import java.nio.file.*;
import java.util.*;

/** External public-method observer; no private-field reads or controller mutation. */
public class W2NativeObserver {
  record Request(String id,ObjectReference function,ObjectReference monitor){}
  static void append(Path out,String text)throws Exception {Files.writeString(out,text+"\n",StandardOpenOption.CREATE,StandardOpenOption.APPEND);}
  static void boundary(VirtualMachine vm,ThreadReference thread,Request request,String kind,Value result,long codeIndex)throws Exception {
    var types=vm.classesByName("W2NormalProbe");if(types.isEmpty())return;
    var type=(ClassType)types.getFirst();var methods=type.methodsByName("nativeBoundary");
    // Mirrored strings may otherwise be collected between JDI calls while other threads run.
    var kindValue=vm.mirrorOf(kind);kindValue.disableCollection();
    var idValue=vm.mirrorOf(request.id());idValue.disableCollection();
    try{type.invokeMethod(thread,methods.getFirst(),Arrays.asList(request.function(),request.monitor(),kindValue,idValue,result,vm.mirrorOf(codeIndex)),ObjectReference.INVOKE_SINGLE_THREADED);}
    finally{kindValue.enableCollection();idValue.enableCollection();}
  }
  static void installEntry(EventRequestManager manager,ReferenceType type)throws Exception {
    if(type.name().equals("ghidra.app.decompiler.DecompInterface")) {
      var method=type.methodsByName("decompileFunction").getFirst();
      // Pinned 12.1.3 bytecodes: javap receipt verifies both actual ARETURN sites.
      for(long index:new long[]{method.location().codeIndex(),61,396}) {
        if(index!=method.location().codeIndex() && (method.bytecodes()[(int)index]&255)!=176)throw new IllegalStateException("Pinned return opcode differs");
        var request=manager.createBreakpointRequest(method.locationOfCodeIndex(index));request.putProperty("boundary",index==method.location().codeIndex()?"start":"terminal");request.setSuspendPolicy(EventRequest.SUSPEND_EVENT_THREAD);request.enable();
      }
    }else if(type.name().equals("ghidra.app.decompiler.DecompileResults")) {
      for(var method:type.methodsByName("<init>")) {
        if(method.argumentTypeNames().isEmpty() || !method.argumentTypeNames().getFirst().equals("ghidra.program.model.listing.Function"))continue;
        var request=manager.createBreakpointRequest(method.location());request.putProperty("boundary","result-constructor");request.setSuspendPolicy(EventRequest.SUSPEND_EVENT_THREAD);request.enable();
      }
    }else if(type.name().equals("ghidra.app.decompiler.DecompileCallback")) {
      var method=type.methodsByName("getPcodeInject").getFirst();
      var request=manager.createBreakpointRequest(method.location());request.putProperty("boundary","injection-request");request.setSuspendPolicy(EventRequest.SUSPEND_EVENT_THREAD);request.enable();
    }
  }
  public static void main(String[] args)throws Exception {
    var connector=Bootstrap.virtualMachineManager().attachingConnectors().stream().filter(c->c.name().equals("com.sun.jdi.SocketAttach")).findFirst().orElseThrow();
    var options=connector.defaultArguments();options.get("hostname").setValue("127.0.0.1");options.get("port").setValue(args[0]);
    var vm=connector.attach(options);var manager=vm.eventRequestManager();Path out=Path.of(args[1]);
    var prepared=manager.createClassPrepareRequest();prepared.addClassFilter("ghidra.app.decompiler.*");prepared.setSuspendPolicy(EventRequest.SUSPEND_EVENT_THREAD);prepared.enable();
    for(String name:List.of("ghidra.app.decompiler.DecompInterface","ghidra.app.decompiler.DecompileResults","ghidra.app.decompiler.DecompileCallback"))for(var type:vm.classesByName(name))installEntry(manager,type);
    var exceptions=manager.createExceptionRequest(null,true,true);exceptions.addClassFilter("fi.gekkio.ghidraboy.*");exceptions.setSuspendPolicy(EventRequest.SUSPEND_EVENT_THREAD);exceptions.enable();
    var active=new HashMap<Long,Request>();var results=new HashMap<Long,ObjectReference>();long counter=0;
    append(out,"observer-installed\t"+System.nanoTime()+"\tpublic-decompileFunction-entry-return-breakpoints; public-result-constructor; public injection getPcode boundaries; provider exceptions; suspend-event-thread; callback-public-support-method; no private field reads");
    vm.resume();
    try {while(true){var set=vm.eventQueue().remove();try{
      for(var event:set) {
        if(event instanceof ClassPrepareEvent e){installEntry(manager,e.referenceType());}
        else if(event instanceof BreakpointEvent e&&"start".equals(e.request().getProperty("boundary"))){
          var values=e.thread().frame(0).getArgumentValues();var request=new Request("native-"+(++counter),(ObjectReference)values.getFirst(),(ObjectReference)values.get(2));
          request.function().disableCollection();if(request.monitor()!=null)request.monitor().disableCollection();
          if(active.put(e.thread().uniqueID(),request)!=null)throw new IllegalStateException("Nested native request");
          append(out,"request-start\t"+System.nanoTime()+"\t"+request.id()+"\tthread="+e.thread().uniqueID()+"\tfunction_object="+request.function().uniqueID());
          boundary(vm,e.thread(),request,"start",null,e.location().codeIndex());
        }else if(event instanceof BreakpointEvent e&&"result-constructor".equals(e.request().getProperty("boundary"))){
          var request=active.get(e.thread().uniqueID());if(request!=null){
            var function=e.thread().frame(0).getArgumentValues().getFirst();
            if(!function.equals(request.function()))throw new IllegalStateException("Result function differs from active native request");
            var result=e.thread().frame(0).thisObject();result.disableCollection();results.put(e.thread().uniqueID(),result);
          }
        }else if(event instanceof BreakpointEvent e&&"injection-request".equals(e.request().getProperty("boundary"))){
          var request=active.get(e.thread().uniqueID());if(request==null)throw new IllegalStateException("Injection request without active native request");
          var values=e.thread().frame(0).getArgumentValues();
          append(out,"injection-request\t"+System.nanoTime()+"\t"+request.id()+"\tthread="+e.thread().uniqueID()+"\tname="+((StringReference)values.get(0)).value()+"\ttype="+((IntegerValue)values.get(2)).value());
        }else if(event instanceof BreakpointEvent e&&"terminal".equals(e.request().getProperty("boundary"))){
          var request=active.remove(e.thread().uniqueID());if(request==null)throw new IllegalStateException("Unmatched native terminal");
          var result=results.remove(e.thread().uniqueID());if(result==null)throw new IllegalStateException("Missing constructed native result");
          append(out,"request-terminal\t"+System.nanoTime()+"\t"+request.id()+"\tthread="+e.thread().uniqueID()+"\tresult_object="+result.uniqueID());
          try{boundary(vm,e.thread(),request,"terminal",result,e.location().codeIndex());}
          finally{result.enableCollection();request.function().enableCollection();if(request.monitor()!=null)request.monitor().enableCollection();}
        }else if(event instanceof ExceptionEvent e){
          var request=active.get(e.thread().uniqueID());
          var method=e.exception().referenceType().methodsByName("toString","()Ljava/lang/String;").getFirst();
          var message=(StringReference)e.exception().invokeMethod(e.thread(),method,List.of(),ObjectReference.INVOKE_SINGLE_THREADED);
          append(out,"provider-exception\t"+System.nanoTime()+"\t"+(request==null?"UNMATCHED":request.id())+"\tthread="+e.thread().uniqueID()+"\texception_object="+e.exception().uniqueID()+"\texception_class="+e.exception().referenceType().name()+"\tlocation="+e.location()+"\tmessage="+message.value().replace('\n',' '));
        }else if(event instanceof VMDeathEvent){append(out,"vm-death\t"+System.nanoTime()+"\tactive_requests="+active.size());return;}
      }
    }finally{set.resume();}}}catch(VMDisconnectedException done){append(out,"vm-disconnect\t"+System.nanoTime()+"\tactive_requests="+active.size());}
  }
}
