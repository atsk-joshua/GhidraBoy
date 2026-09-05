package fi.gekkio.ghidraboy;

import ghidra.program.model.listing.*;
import ghidra.program.model.data.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import java.util.*;

/** Per-function, explicit ABI selection backed by pinned compiler fixtures and Ghidra models. */
public final class CompilerAbi {
    private CompilerAbi() { }
    public record Parameter(String name,String type,String storage) { }
    public record Request(String profile,String returnType,String returnStorage,List<Parameter> parameters,
                          Integer stackPurgeBytes,String callingConvention) { }
    public record Storage(String name,String type,String storage) { }
    public record Plan(String callingConvention,Storage returns,List<Storage> parameters,int stackPurgeBytes,boolean variadic,List<String> limitations) { }
    private record Allocation(Plan plan,DataType returns,List<DataType> types,VariableStorage returnStorage,List<VariableStorage> storage) { }
    private static DataType type(String name) {
        return switch(name) {
            case "void" -> VoidDataType.dataType; case "u8" -> ByteDataType.dataType; case "u16" -> WordDataType.dataType;
            case "u32" -> DWordDataType.dataType; case "ptr" -> new PointerDataType(ByteDataType.dataType,2);
            default -> {
                if(!name.startsWith("bytes:")) throw new IllegalArgumentException("Type must be void/u8/u16/u32/ptr or explicit bytes:N");
                int size=Integer.parseInt(name.substring(6));
                if(size<1 || size>256) throw new IllegalArgumentException("Aggregate size outside 1..256");
                yield new ArrayDataType(ByteDataType.dataType,size,1);
            }
        };
    }
    private static VariableStorage storage(Program p,String text,int size) throws Exception {
        if(size==0) return VariableStorage.VOID_STORAGE;
        if(text==null) throw new IllegalArgumentException("Explicit storage required");
        if(text.startsWith("stack:")) return new VariableStorage(p,p.getAddressFactory().getStackSpace().getAddress(Integer.decode(text.substring(6))),size);
        var parts=new ArrayList<Varnode>();
        for(String name:text.split(":")) {
            var register=p.getRegister(name); if(register==null) throw new IllegalArgumentException("Unknown register "+name);
            parts.add(new Varnode(register.getAddress(),register.getMinimumByteSize()));
        }
        var result=new VariableStorage(p,parts.toArray(Varnode[]::new));
        if(result.size()!=size) throw new IllegalArgumentException("Storage size differs from data type");
        return result;
    }
    private static Allocation allocate(Program p,Request request) throws Exception {
        var returnType=type(request.returnType()); var types=request.parameters().stream().map(parameter->type(parameter.type())).toList();
        boolean explicit=request.profile().equals("explicit");
        if(types.stream().anyMatch(t->t.getLength()<=0)) throw new IllegalArgumentException("Parameters cannot be void");
        if(!explicit && (request.returnType().startsWith("bytes:") || request.parameters().stream().anyMatch(param->param.type().startsWith("bytes:"))))
            throw new IllegalArgumentException("Aggregate ABI requires explicit hidden/result parameters and storage from emitted code");
        String convention=switch(request.profile()) {
            case "sdcc416" -> "__sdcc416";
            case "sdcc451-call0" -> "__sdcc451_call0";
            case "sdcc451-call1" -> "__sdcc451_call1_first"+(types.isEmpty()?8:types.get(0).getLength()*8);
            case "sdcc451-variadic" -> "__sdcc451_variadic";
            case "sdcc451-banked-callee" -> "__sdcc451_banked_callee";
            case "sdcc451-preserves-bc" -> "__sdcc451_preserves_bc";
            case "explicit" -> request.callingConvention()==null?"__asm":request.callingConvention();
            default -> throw new IllegalArgumentException("Unknown ABI profile");
        };
        if(request.profile().equals("sdcc451-preserves-bc") && (returnType.getLength()>1 || types.size()!=1 || types.get(0).getLength()!=1))
            throw new IllegalArgumentException("Preserved-BC fixture establishes one u8 argument and u8/void return only");
        var model=p.getCompilerSpec().getCallingConvention(convention);
        if(model==null) throw new IllegalArgumentException("Convention not installed: "+convention);
        var storage=new ArrayList<VariableStorage>(); VariableStorage result;
        if(explicit) {
            result=storage(p,request.returnStorage(),returnType.getLength());
            for(int i=0;i<types.size();i++) storage.add(storage(p,request.parameters().get(i).storage(),types.get(i).getLength()));
        } else {
            result=model.getStorageLocations(p,new DataType[]{returnType},false)[0];
            boolean registers=request.profile().equals("sdcc451-call1") || request.profile().equals("sdcc451-preserves-bc");
            int stack=request.profile().equals("sdcc451-banked-callee")?6:2;
            int first=types.isEmpty()?0:types.get(0).getLength();
            for(int i=0;i<types.size();i++) {
                int size=types.get(i).getLength(); String register=null;
                if(registers && i==0) register=switch(size) { case 1 -> "A"; case 2 -> "DE"; case 4 -> "DE:BC"; default -> null; };
                if(registers && i==1 && size<=2) {
                    if(first==1) register=size==1?"E":"DE";
                    else if(first==2) register=size==1?"A":"BC";
                }
                if(register!=null) storage.add(storage(p,register,size));
                else { storage.add(storage(p,"stack:"+stack,size)); stack+=size; }
            }
            // SDCC packs stack arguments to bytes. Ghidra's generic allocator uses
            // datatype alignment even with pentry align=1, so install explicit
            // per-function storage instead of changing global data organization.
        }
        int purge=0;
        if(request.profile().equals("sdcc451-call1") || request.profile().equals("sdcc451-preserves-bc"))
            for(var place:storage) if(place.isStackStorage()) purge+=place.size();
        if(explicit) {
            if(request.stackPurgeBytes()==null || request.stackPurgeBytes()<0 || request.stackPurgeBytes()>65535) throw new IllegalArgumentException("Explicit callee stack purge required (excluding return address)");
            purge=request.stackPurgeBytes();
        }
        var parameters=new ArrayList<Storage>();
        for(int i=0;i<types.size();i++) parameters.add(new Storage(request.parameters().get(i).name(),request.parameters().get(i).type(),storage.get(i).toString()));
        var limitations=request.profile().equals("sdcc451-banked-callee")?List.of("Callee entry storage only; bcall helper and live banking are not modeled"):
            explicit?List.of("User-supplied storage/cleanup; caller must validate against emitted code"):List.<String>of();
        return new Allocation(new Plan(convention,new Storage("return",request.returnType(),result.toString()),parameters,purge,request.profile().equals("sdcc451-variadic"),limitations),returnType,types,result,storage);
    }
    public static Plan preview(Program p,Request request) throws Exception { return allocate(p,request).plan; }
    public static Plan apply(Program p,Function function,Request request) throws Exception {
        if(function==null) throw new IllegalArgumentException("Select an existing function");
        var allocation=allocate(p,request);int tx=p.startTransaction("Apply explicit per-function SM83 ABI");boolean success=false;
        try {
            var parameters=new ArrayList<Variable>();
            for(int i=0;i<allocation.types.size();i++) parameters.add(new ParameterImpl(request.parameters().get(i).name(),allocation.types.get(i),allocation.storage.get(i),p));
            var returns=new ReturnParameterImpl(allocation.returns,allocation.returnStorage,p);
            function.updateFunction(allocation.plan.callingConvention(),returns,parameters,Function.FunctionUpdateType.CUSTOM_STORAGE,true,SourceType.USER_DEFINED);
            function.setVarArgs(allocation.plan.variadic());function.setStackPurgeSize(allocation.plan.stackPurgeBytes());
            p.getOptions(ProgramMapping.OPTIONS).setString("abi."+function.getSymbol().getID(),ProgramMapping.JSON.toJson(request));
            success=true;
        } finally { p.endTransaction(tx,success); }
        return allocation.plan;
    }
}
