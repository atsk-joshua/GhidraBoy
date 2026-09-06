// Isolated diagnostic transport for native normalized-switch override testing.
// No Program symbols, overrides, signatures or instruction definitions are written.
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.*;
import java.io.IOException;
import java.lang.reflect.*;
import java.util.*;
import static ghidra.program.model.pcode.ElementId.*;
import static ghidra.program.model.pcode.AttributeId.*;

public class NormalizedSwitchDecompiler extends DecompInterface {
    public record Norm(Address address,long hash) {}
    private final Address functionEntry,branch;
    private final List<Address> targets;
    private final Norm norm;
    private int injections;
    public NormalizedSwitchDecompiler(Address functionEntry,Address branch,List<Address> targets,Norm norm) {
        this.functionEntry=functionEntry;this.branch=branch;this.targets=List.copyOf(targets);this.norm=norm;
    }
    public int getInjections(){return injections;}
    private void encodeOverride(Encoder encoder)throws IOException {
        encoder.openElement(ELEM_JUMPTABLELIST);encoder.openElement(ELEM_JUMPTABLE);
        AddressXML.encode(encoder,branch);encoder.openElement(ELEM_BASICOVERRIDE);
        for(var target:targets){encoder.openElement(ELEM_DEST);AddressXML.encodeAttributes(encoder,target);encoder.closeElement(ELEM_DEST);}
        if(norm!=null) {
            encoder.openElement(ELEM_NORMADDR);AddressXML.encodeAttributes(encoder,norm.address());encoder.closeElement(ELEM_NORMADDR);
            encoder.openElement(ELEM_NORMHASH);encoder.writeUnsignedInteger(ATTRIB_CONTENT,norm.hash());encoder.closeElement(ELEM_NORMHASH);
            encoder.openElement(ELEM_STARTVAL);encoder.writeUnsignedInteger(ATTRIB_CONTENT,0);encoder.closeElement(ELEM_STARTVAL);
        }
        encoder.closeElement(ELEM_BASICOVERRIDE);encoder.closeElement(ELEM_JUMPTABLE);encoder.closeElement(ELEM_JUMPTABLELIST);injections++;
    }
    @Override protected void initializeProcess()throws IOException,DecompileException {
        if(!(decompCallback instanceof Callback))decompCallback=new Callback();
        super.initializeProcess();
    }
    private class Callback extends DecompileCallback {
        Callback(){super(program,program.getLanguage(),program.getCompilerSpec(),NormalizedSwitchDecompiler.this.getDataTypeManager());}
        @Override public void getMappedSymbols(Address address,Encoder destination)throws IOException {
            if(!address.equals(functionEntry)){super.getMappedSymbols(address,destination);return;}
            Encoder decorated=(Encoder)Proxy.newProxyInstance(Encoder.class.getClassLoader(),new Class[]{Encoder.class},(proxy,method,args)->{
                if(method.getName().equals("openElement")&&args[0].equals(ELEM_JUMPTABLELIST))
                    throw new IOException("Existing jump override preserved; diagnostic refuses replacement");
                if(method.getName().equals("closeElement")&&args[0].equals(ELEM_FUNCTION))encodeOverride(destination);
                try{return method.invoke(destination,args);}catch(InvocationTargetException error){throw error.getCause();}
            });
            super.getMappedSymbols(address,decorated);
        }
    }
}
