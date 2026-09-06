package ghigbc;

import java.awt.*;
import java.util.*;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.nio.file.Path;
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
    private final JLabel status=new JLabel("Select a captured GB/GBC trace to inspect history.");
    private final DefaultTableModel events=new DefaultTableModel(new String[]{"Sequence","Snapshot","Epoch","Physical target","Before","After","Access","Instruction","Caller"},0){public boolean isCellEditable(int r,int c){return false;}};
    private final JTable eventTable=new JTable(events);
    private final JTextArea eventDetails=new JTextArea("Select an access to inspect its physical target and capture precision.",4,40);
    private long selectedSnapshot;
    private Trace selectedTrace;
    private final JTextField filter=new JTextField(24);
    private final JComboBox<String> region=new JComboBox<>(new String[]{"wram","rom","vram","cart","boot","cpu","oam","hram","io"});
    private final JTextField bank=new JTextField("0",3),offset=new JTextField("0",6),length=new JTextField("64",4);
    private final JLabel operation=new JLabel("Captured observations only; no live memory reads.");
    private JsonObject pinned;
    private SwingWorker<?,?> activeWork;
    private final java.util.List<JButton> reportButtons=new ArrayList<>();
    private final TableRowSorter<DefaultTableModel> sorter=new TableRowSorter<>(events);
    private int selectedEvent(){int row=eventTable.getSelectedRow();return row<0?-1:eventTable.convertRowIndexToModel(row);}

    private final java.util.List<TraceObject> eventObjects=new ArrayList<>();
    public StudyProvider(PluginTool tool,GbcPlugin plugin){
        super(tool,"GBC History","GhiGBC");this.tool=tool;
        JPanel header=new JPanel(new BorderLayout());header.add(status,BorderLayout.NORTH);
        JPanel search=new JPanel(new FlowLayout(FlowLayout.LEADING));JLabel searchLabel=new JLabel("Filter history:");searchLabel.setLabelFor(filter);searchLabel.setDisplayedMnemonic('F');search.add(searchLabel);search.add(filter);
        filter.setToolTipText("Exact filters: region:wram bank:1 offset:0x23 epoch:2 access:write. Other words search displayed columns.");
        filter.getDocument().addDocumentListener(new DocumentListener(){public void insertUpdate(DocumentEvent e){applyFilter();}public void removeUpdate(DocumentEvent e){applyFilter();}public void changedUpdate(DocumentEvent e){applyFilter();}});
        eventTable.setRowSorter(sorter);header.add(search,BorderLayout.SOUTH);panel.add(header,BorderLayout.NORTH);
        eventDetails.setEditable(false);eventDetails.setLineWrap(true);eventDetails.setWrapStyleWord(true);
        eventDetails.setFont(UIManager.getFont("Label.font"));
        JPanel writes=new JPanel(new BorderLayout());writes.add(new JScrollPane(eventTable));writes.add(new JScrollPane(eventDetails),BorderLayout.SOUTH);
        eventTable.getSelectionModel().addListSelectionListener(e->{
            int row=selectedEvent();
            eventDetails.setText(row>=0&&row<eventObjects.size()?eventDescription(eventObjects.get(row),selectedSnapshot):"Select an access to inspect its physical target and capture precision.");
            eventDetails.setCaretPosition(0);
        });
        panel.add(writes);
        JPanel buttons=new JPanel();
        JButton writer=new JButton("Go to writer");writer.addActionListener(e->{int row=selectedEvent();if(row>=0)plugin.goWriter(eventObjects.get(row),false);});buttons.add(writer);
        JButton bookmark=new JButton("Bookmark observation");bookmark.addActionListener(e->{int row=selectedEvent();if(row>=0)plugin.goWriter(eventObjects.get(row),true);});buttons.add(bookmark);
        JPanel footer=new JPanel(new BorderLayout());footer.add(buttons,BorderLayout.NORTH);
        JPanel reports=new JPanel(new FlowLayout(FlowLayout.LEADING));JLabel rangeLabel=new JLabel("Capture range:");rangeLabel.setLabelFor(region);reports.add(rangeLabel);reports.add(region);
        addField(reports,"Bank",bank);addField(reports,"Offset",offset);addField(reports,"Length",length);
        offset.setToolTipText("Physical offset in decimal or 0x hexadecimal; export at most 4096 bytes.");
        addReportButton(reports,"Pin capture",()->captureOperation("Pin capture",report->{pinned=report;operation.setText("Pinned snapshot "+report.getAsJsonObject("observation").get("snapshot"));}));
        addReportButton(reports,"Compare capture",()->{if(pinned==null){operation.setText("Pin or reopen a capture first.");return;}captureOperation("Compare capture",report->showReport("Capture comparison",ObservationReport.compare(pinned,report)));});
        addReportButton(reports,"Export capture",()->exportCapture());addReportButton(reports,"Reopen observation",()->reopenObservation());
        JButton cancel=new JButton("Cancel");cancel.addActionListener(e->{if(activeWork!=null)activeWork.cancel(true);});reports.add(cancel);
        JScrollPane controls=new JScrollPane(reports,JScrollPane.VERTICAL_SCROLLBAR_NEVER,JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);controls.setBorder(null);footer.add(controls,BorderLayout.CENTER);footer.add(operation,BorderLayout.SOUTH);panel.add(footer,BorderLayout.SOUTH);tool.addComponentProvider(this,true);
    }
    private static void addField(JPanel panel,String name,JTextField field){JLabel label=new JLabel(name);label.setLabelFor(field);panel.add(label);panel.add(field);}
    private void addReportButton(JPanel panel,String label,Runnable action){JButton button=new JButton(label);button.setMnemonic(label.charAt(0));button.addActionListener(e->action.run());reportButtons.add(button);panel.add(button);}
    private void applyFilter(){
        final HistoryFilter parsed;try{parsed=new HistoryFilter(filter.getText());}catch(IllegalArgumentException error){operation.setText(error.getMessage());return;}
        sorter.setRowFilter(new RowFilter<DefaultTableModel,Integer>(){public boolean include(Entry<? extends DefaultTableModel,? extends Integer> entry){
            int row=entry.getIdentifier();if(row<0||row>=eventObjects.size())return false;
            var text=new StringBuilder();for(int i=0;i<entry.getValueCount();i++)text.append(entry.getStringValue(i)).append(' ');
            return parsed.matches(eventObjects.get(row),selectedSnapshot,text.toString());
        }});
        operation.setText("Showing "+eventTable.getRowCount()+" of "+events.getRowCount()+" captured events.");
    }
    private ObservationReport.Selection range(){return new ObservationReport.Selection((String)region.getSelectedItem(),Integer.decode(bank.getText().trim()),Integer.decode(offset.getText().trim()),Integer.decode(length.getText().trim()));}
    private void showReport(String title,String report){JTextArea text=new JTextArea(report,28,100);text.setEditable(false);text.setCaretPosition(0);JOptionPane.showMessageDialog(panel,new JScrollPane(text),title,JOptionPane.PLAIN_MESSAGE);}
    private <T> void background(String label,java.util.concurrent.Callable<T> work,java.util.function.Consumer<T> done){
        if(activeWork!=null)return;
        operation.setText(label+"…");reportButtons.forEach(b->b.setEnabled(false));
        activeWork=new SwingWorker<T,Void>(){
            protected T doInBackground()throws Exception{return work.call();}
            protected void done(){
                try{T result=get();operation.setText(label+" complete.");done.accept(result);}
                catch(java.util.concurrent.CancellationException error){operation.setText(label+" cancelled.");}
                catch(Exception error){Throwable cause=error.getCause()==null?error:error.getCause();operation.setText(label+" failed: "+cause.getMessage());}
                finally{activeWork=null;reportButtons.forEach(b->b.setEnabled(true));}
            }
        };activeWork.execute();
    }
    private void captureOperation(String label,java.util.function.Consumer<JsonObject> done){
        try {
            Trace trace=selectedTrace;long snap=selectedSnapshot;var range=range();if(trace==null||trace.isClosed())throw new IllegalArgumentException("Select a captured trace first.");
            background(label,()->{Object consumer=new Object();trace.addConsumer(consumer);try{return ObservationReport.capture(trace,snap,range);}finally{trace.release(consumer);}},done);
        }catch(RuntimeException error){operation.setText(error.getMessage());}
    }
    private void exportCapture(){
        JFileChooser chooser=new JFileChooser();chooser.setDialogTitle("Export selected capture observation");chooser.setSelectedFile(new java.io.File("observation.json"));
        if(chooser.showSaveDialog(panel)!=JFileChooser.APPROVE_OPTION)return;
        Path path=chooser.getSelectedFile().toPath();if(java.nio.file.Files.exists(path)&&JOptionPane.showConfirmDialog(panel,"Replace "+path.getFileName()+"?","Export observation",JOptionPane.YES_NO_OPTION)!=JOptionPane.YES_OPTION)return;
        // Freeze the trace/snapshot/range before asynchronous work starts.
        try{Trace trace=selectedTrace;long snap=selectedSnapshot;var range=range();if(trace==null||trace.isClosed())throw new IllegalArgumentException("Select a captured trace first.");
            background("Export capture",()->{Object consumer=new Object();trace.addConsumer(consumer);try{var report=ObservationReport.capture(trace,snap,range);ObservationReport.write(path,report);return path;}finally{trace.release(consumer);}},saved->operation.setText("Exported selected snapshot "+snap+" to "+saved));
        }catch(RuntimeException error){operation.setText(error.getMessage());}
    }
    private void reopenObservation(){
        JFileChooser chooser=new JFileChooser();chooser.setDialogTitle("Reopen captured observation");if(chooser.showOpenDialog(panel)!=JFileChooser.APPROVE_OPTION)return;
        Path path=chooser.getSelectedFile().toPath();background("Reopen observation",()->ObservationReport.read(path,null),report->{pinned=report;showReport("Reopened observation (pinned for comparison)",ObservationReport.describe(report));});
    }
    public static Object value(TraceObject object,long snap,String name){return ObservationReport.value(object,snap,name);}
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

        selectedSnapshot=snap;selectedTrace=t;eventObjects.clear();events.setRowCount(0);
        if(t==null||t.isClosed()){status.setText("No selected trace");return;}
        var m=t.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine"));if(m==null){status.setText("Selected trace has no captured GBC machine.");return;}
        Object marker=value(m,snap,"CaptureSnapshot");
        if(!(marker instanceof Number number)||number.longValue()!=snap){status.setText("Capture unavailable or still being published.");return;}
        status.setText("Captured snapshot "+snap+" · session "+shown(value(m,snap,"Session"))+" · epoch "+shown(value(m,snap,"Epoch"))+" · "+shown(value(m,snap,"Backend"))+" / "+shown(value(m,snap,"Model"))+" · "+shown(value(m,snap,"ObservationState")));
        var container=t.getObjectManager().getObjectByCanonicalPath(KeyPath.parse("Machine.Events"));if(container==null)return;
        for(var entry:container.getElements(ghidra.trace.model.Lifespan.at(snap))) {
            if(!(entry.getValue() instanceof TraceObject event))continue;
            eventObjects.add(event);events.addRow(new Object[]{entry.getEntryKey(),value(event,snap,"Snapshot"),"epoch "+shown(value(event,snap,"Epoch")),physicalLabel(event,snap),Boolean.TRUE.equals(value(event,snap,"Valid"))?value(event,snap,"Before"):"unknown",Boolean.TRUE.equals(value(event,snap,"Valid"))?value(event,snap,"After"):"unknown",accessLabel(value(event,snap,"Access")),writerLabel(t,event,snap,currentProgram()),"unknown"});
        }
    }
    private ghidra.program.model.listing.Program currentProgram(){var manager=tool.getService(ghidra.app.services.ProgramManager.class);return manager==null?null:manager.getCurrentProgram();}
    private static String accessLabel(Object access){if(!(access instanceof Number n))return "unknown";return switch(n.intValue()){case 1->"execute";case 2->"read";case 4->"write";default->"unknown ("+n+")";};}
    private static String physicalLabel(TraceObject event,long snap){String[] names={"cpu","rom","wram","vram","cart","boot","oam","hram","io","unknown"};Object region=value(event,snap,"TargetRegion");int index=region instanceof Number n?n.intValue():-1;return (index>=0&&index<names.length?names[index]:"unknown")+" bank "+shown(value(event,snap,"TargetBank"))+" +"+hex(value(event,snap,"TargetOffset"));}
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
