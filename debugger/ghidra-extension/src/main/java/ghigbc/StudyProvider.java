package ghigbc;

import java.awt.*;
import java.util.*;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import com.google.gson.*;
import docking.ComponentProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.path.KeyPath;

/** Captured values always come from the selected trace snapshot, never live emulation. */
public class StudyProvider extends ComponentProvider {
    private final PluginTool tool;
    private Trace renderedTrace;
    private long renderedSnap=Long.MIN_VALUE;
    private boolean renderedMapped;
    private final JPanel panel=new JPanel(new BorderLayout());
    private final JLabel status=new JLabel("Open a matching program and captured GBC trace.");
    private final DefaultTableModel events=new DefaultTableModel(new String[]{"Sequence","Snapshot","Epoch","Before","After","Access","Instruction","Caller"},0){public boolean isCellEditable(int r,int c){return false;}};
    private final JTable eventTable=new JTable(events);
    private final JTextArea eventDetails=new JTextArea("Select a write to inspect its physical target and capture precision.",4,40);
    private long selectedSnapshot;
    private final java.util.List<TraceObject> eventObjects=new ArrayList<>();
    public StudyProvider(PluginTool tool,GbcPlugin plugin){
        super(tool,"GBC History","GhiGBC");this.tool=tool;
        panel.add(status,BorderLayout.NORTH);
        eventDetails.setEditable(false);eventDetails.setLineWrap(true);eventDetails.setWrapStyleWord(true);
        eventDetails.setFont(UIManager.getFont("Label.font"));
        JPanel writes=new JPanel(new BorderLayout());writes.add(new JScrollPane(eventTable));writes.add(new JScrollPane(eventDetails),BorderLayout.SOUTH);
        eventTable.getSelectionModel().addListSelectionListener(e->{
            int row=eventTable.getSelectedRow();
            eventDetails.setText(row>=0&&row<eventObjects.size()?eventDescription(eventObjects.get(row),selectedSnapshot):"Select a write to inspect its physical target and capture precision.");
            eventDetails.setCaretPosition(0);
        });
        panel.add(writes);
        JPanel buttons=new JPanel();
        JButton writer=new JButton("Go to writer");writer.addActionListener(e->{int row=eventTable.getSelectedRow();if(row>=0)plugin.goWriter(eventObjects.get(row),false);});buttons.add(writer);
        JButton bookmark=new JButton("Bookmark observation");bookmark.addActionListener(e->{int row=eventTable.getSelectedRow();if(row>=0)plugin.goWriter(eventObjects.get(row),true);});buttons.add(bookmark);
        panel.add(buttons,BorderLayout.SOUTH);tool.addComponentProvider(this,true);
    }
    public static Object value(TraceObject object,long snap,String name){var v=object.getValue(snap,name);return v==null?null:v.getValue();}
    public void refresh(Trace t,long snap){
        if(t!=null&&!t.isClosed()) {
            var machine=t.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine"));
            var complete=machine==null?null:value(machine,snap,"CaptureSnapshot");
            boolean mapped=ghigbc.BankMappings.isReady(machine,snap);
            if(complete instanceof Number n&&n.longValue()==snap){
                if(t==renderedTrace&&snap==renderedSnap&&mapped==renderedMapped)return;
                renderedTrace=t;renderedSnap=snap;renderedMapped=mapped;
            }
        }else{renderedTrace=null;renderedSnap=Long.MIN_VALUE;}

        selectedSnapshot=snap;eventObjects.clear();events.setRowCount(0);
        if(t==null||t.isClosed()){status.setText("No selected trace");return;}
        var m=t.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine"));if(m==null)return;
        Object marker=value(m,snap,"CaptureSnapshot");
        if(!(marker instanceof Number number)||number.longValue()!=snap){status.setText("Capture unavailable or still being published.");return;}
        status.setText("Snapshot "+snap+" · "+value(m,snap,"Profile")+" · "+value(m,snap,"ProfileError"));
        var container=t.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine.Events"));if(container==null)return;
        for(var entry:container.getElements(ghidra.trace.model.Lifespan.at(snap))) {
            if(!(entry.getValue() instanceof TraceObject event))continue;
            eventObjects.add(event);events.addRow(new Object[]{entry.getEntryKey(),value(event,snap,"Snapshot"),value(event,snap,"Epoch"),Boolean.TRUE.equals(value(event,snap,"Valid"))?value(event,snap,"Before"):"unknown",Boolean.TRUE.equals(value(event,snap,"Valid"))?value(event,snap,"After"):"unknown",Integer.valueOf(4).equals(value(event,snap,"Access"))||Long.valueOf(4).equals(value(event,snap,"Access"))?"write":"read",writerLabel(t,event,snap,tool.getService(ghidra.app.services.ProgramManager.class).getCurrentProgram()),"unknown"});
        }
    }
    private static String hex(Object value){return value instanceof Number n?"0x"+Long.toHexString(n.longValue()):"unknown";}
    private static String shown(Object value){return value==null?"unknown":value.toString();}
    public static String eventDescription(TraceObject event,long selected){
        Object time=value(event,selected,"Snapshot");if(!(time instanceof Number n))return "Capture metadata unavailable.";
        long snap=n.longValue();Object region=value(event,snap,"TargetRegion"),bank=value(event,snap,"TargetBank"),offset=value(event,snap,"TargetOffset");
        String[] names={"cpu","rom","wram","vram","cart","boot","oam","hram","io","unknown"};
        int index=region instanceof Number r?r.intValue():-1;
        String target=(index>=0&&index<names.length?names[index]:"unknown")+" bank "+shown(bank)+" +"+hex(offset);
        return "Target: "+target+"; CPU "+hex(value(event,snap,"TargetCPU"))+"\n"+
            "Origin: "+shown(value(event,snap,"Origin"))+"; attempted access value: "+hex(value(event,snap,"Attempt"))+"\n"+
            "Writer CPU: "+hex(value(event,snap,"WriterPC"))+"; snapshot "+snap+"; epoch "+shown(value(event,snap,"Epoch"))+"\n"+
            "Precision: "+shown(value(event,snap,"Precision"))+". "+(Boolean.TRUE.equals(value(event,snap,"Valid"))?"Before is pre-access; after is the final physical byte.":"Physical before/after unavailable.");
    }
    public static String writerLabel(Trace trace,TraceObject event,long selected,ghidra.program.model.listing.Program program){
        Object observed=value(event,selected,"Writer");
        if(!(observed instanceof ghidra.program.model.address.Address writer)||program==null)return String.valueOf(observed);
        Object time=value(event,selected,"Snapshot");if(!(time instanceof Number n))return writer.toString();
        var map=trace.getStaticMappingManager().findContaining(writer,n.longValue());
        if(map==null||!map.getStaticProgramURL().equals(ghidra.app.plugin.core.debug.utils.ProgramURLUtils.getUrlFromProgram(program)))return writer.toString();
        var address=program.getAddressFactory().getAddress(map.getStaticAddress()).add(writer.subtract(map.getMinTraceAddress()));
        var symbol=program.getSymbolTable().getPrimarySymbol(address);
        if(symbol!=null)return symbol.getName(true)+" @ "+address;
        var function=program.getFunctionManager().getFunctionContaining(address);
        return function==null?address.toString():function.getName(true)+"+0x"+Long.toHexString(address.subtract(function.getEntryPoint()))+" @ "+address;
    }
    @Override public JComponent getComponent(){return panel;}
}
