import fi.gekkio.ghidraboy.*;
import ghigbc.BankMappings;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/** Consumer conformance against real installed provider and real Program memory topology. */
public final class MappingContractTest {
    static void require(boolean ok,String reason){if(!ok)throw new AssertionError(reason);System.out.println("PASS mapping contract: "+reason);}
    public static void run(Program p)throws Exception {
        var initial=new BankMappings(p);String hash=initial.hash();String generation=initial.generation();
        int tx=p.startTransaction("Temporary consumer conformance fixture");
        try {
            var memory=p.getMemory();var bank=memory.getBlock("student_second_bank");var middle=bank.getStart().add(0x100);
            memory.split(bank,middle);memory.getBlock(middle).setName("partial bank with spaces");
            var split=new BankMappings(p);
            require(split.hash().equals(hash)&&split.fullCoverage(),"split/rename retains patched-export identity and full coverage");
            require(split.reverse(middle.add(3)).bank()==2&&split.reverse(middle.add(3)).offset()==0x103,"partial bank preserves physical offset");
            require(!split.generation().equals(generation)&&initial.generation().equals(generation),"topology gets new immutable generation");
            byte original=memory.getByte(middle);memory.setByte(middle,(byte)(original^0x5a));
            require(!new BankMappings(p).hash().equals(hash),"current patched bytes differ from original FileBytes identity");
            require(ProgramMapping.inspect(p).originalSha256().equals(hash),"original file identity remains independent");
            memory.setByte(middle,original);
            var file=ProgramMapping.originalFile(p);
            var alias=memory.createInitializedBlock("second canonical ROM view",p.getAddressFactory().getDefaultAddressSpace().getAddress(0x4000),file,0x4000,0x4000,true);
            var ambiguous=new BankMappings(p);
            require(ambiguous.resolve("rom",1,0x29,0x4029)==null,"ambiguous matching CPU views remain unresolved");
            require(new BankMappings(p,alias.getStart().getAddressSpace().getName()).resolve("rom",1,0x29,0x4029).equals(alias.getStart().add(0x29)),"explicit selected view resolves ambiguity");
            require(ambiguous.candidates("rom",1,0x29).size()>=2,"ambiguous candidates retained for inspection");
            require(ambiguous.reverse(alias.getStart().add(0x29)).bank()==1,"second view reverses without name heuristics");
            require(ProgramMapping.cpuToStatic(p,null,0x4029,false).status().equals("unknown"),"unknown mapper never defaults bank 1");
            require(ProgramMapping.staticToPhysical(p,p.getAddressFactory().getDefaultAddressSpace().getAddress(0xe034)).stream().anyMatch(x->x.region().equals("WRAM")&&x.bank()==0&&x.offset()==0x34),"echo alias uses shared facade vocabulary");
            memory.removeBlock(memory.getBlock(middle),TaskMonitor.DUMMY);
            var partial=new BankMappings(p);
            require(!partial.fullCoverage()&&partial.hash().isEmpty(),"missing Program coverage cannot claim full-image binding");
            require(!partial.candidates("rom",1,0x29).isEmpty(),"partial Program retains exploratory physical candidates");
        } finally {p.endTransaction(tx,false);}
        require(new BankMappings(p).hash().equals(hash),"conformance fixture rolls back without altering user annotations");
    }
}
