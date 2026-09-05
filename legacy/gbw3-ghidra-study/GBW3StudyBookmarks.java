// Add a guided study trail to the reviewed Game Boy Wars 3 Ghidra program.
// Changes only bookmarks. Existing bytes, names, comments and types are preserved.
//@category GBW3
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.mem.MemoryBlock;
import java.security.MessageDigest;

public class GBW3StudyBookmarks extends GhidraScript {
    private static final String EXPECTED = "e779a6b56575a2afafb7e1e99411b23d7400a8fddbda8bd52c660b7903c3b451";
    private static final String CATEGORY = "GBW3 Study";
    private static final String[][] POINTS = {
        {"036f", "01 Existing label correction: calls 0360, which writes a JP instruction to C008-C00A, not C005-C007. Trace 0040 to see why."},
        {"04d2", "02 Rename by purpose: waits for FF8E to change when LCD shadow C00F bit 7 is set. Suggested name WaitForNextFrameIfLCDEnabled."},
        {"ff8e", "02 Frame counter: increment at 04C4; compared by 04D2. Suggested label VBlankFrameCounter."},
        {"rom18::4029", "03 Find a structure: A is unit slot; four doublings yield HL=D000+16*A. Suggested name GetUnitInstanceAddress. Does not select WRAM bank."},
        {"wram3::d000", "03 Live unit array: 100 records, 16 bytes each, through D63F. HP is record +4. Static uninitialized RAM is expected."},
        {"rom18::4037", "04 Template byte accessor: packed type in A, offset in C, result in A; preserves BC and HL. Suggested name ReadUnitTemplateByte."},
        {"rom18::4043", "04 Missing function exercise: disassemble through 404E, create ReadUnitTemplateWord. DE returns low/high bytes; C increases by 1."},
        {"rom18::4a43", "05 Unit template lookup: 53 little-endian 16-bit CPU addresses in bank 18. These are not bank-complete pointers."},
        {"rom18::4aad", "05 Define UnitTemplate[53]: packed size 0x25, ends at 5255. Name glyphs are not ASCII. Keep unknown fields explicit."},
        {"rom18::4ad2", "05 Grunt template, index 1: HP +0A, move +0C, primary weapon ID +14. Check against its live instance."},
        {"rom18::5298", "06 Define WeaponTemplate[33]: packed size 0x10, ends at 54A7. Attack array +0A..+0E indexed by target class."},
        {"rom12::47cc", "07 Custom far call: EF 12 37 40 -> rom18::4037; inline arguments are 47CD-47CF; execution resumes at 47D0. Trace dispatcher 3B06."},
        {"3b06", "07 Existing FUN_rst28 dispatches an inline bank/address call. At 3B16 it advances the stored return address by three bytes."},
        {"rom12::484a", "08 Small arithmetic function: A -> max(1, floor(A/10)*10). Suggested name GroupInitiative. Work through inputs 9, 10, 19, 20."},
        {"rom12::4b0a", "09 ResolveCombatOrder: compare attacker DBCF and defender DBE4. Paths: attacker first 4B18, defender first 4B35, equal 4B52."},
        {"rom12::4b52", "09 Simultaneous case: PUSH AF saves first result while second calculation still sees original HP. Only then are both results stored."},
        {"wram4::dbc8", "09 Combat scratch begins here: attacker slot DBC8, defender DBC9. Working HP DBD3/DBE8, initiative DBCF/DBE4. See guide."},
        {"rom12::4b67", "10 Follow results back to live state: combat commit routine. Follow calls to rom18::40A1 with offset C=4 to locate HP writes."}
    };

    public void run() throws Exception {
        if (currentProgram == null || !currentProgram.getLanguageID().toString().equals("SM83:LE:16:default")) {
            throw new IllegalStateException("Open the reviewed SM83 Game Boy Wars 3 program first.");
        }
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        for (int bank = 0; bank < 64; bank++) {
            MemoryBlock block = currentProgram.getMemory().getBlock("rom" + bank);
            if (block == null || !block.isInitialized() || block.getSize() != 0x4000) {
                throw new IllegalStateException("Expected rom0..rom63 memory blocks; no bookmarks added.");
            }
            byte[] bytes = new byte[0x4000];
            currentProgram.getMemory().getBytes(block.getStart(), bytes);
            digest.update(bytes);
        }
        StringBuilder hash = new StringBuilder();
        for (byte b : digest.digest()) hash.append(String.format("%02x", b & 255));
        if (!EXPECTED.equals(hash.toString())) {
            throw new IllegalStateException("ROM bytes differ from the reviewed GZF; no bookmarks added. Use the guide to verify addresses manually.");
        }
        Address[] addresses = new Address[POINTS.length];
        for (int i = 0; i < POINTS.length; i++) {
            addresses[i] = currentProgram.getAddressFactory().getAddress(POINTS[i][0]);
            if (addresses[i] == null || !currentProgram.getMemory().contains(addresses[i])) {
                throw new IllegalStateException("Missing address " + POINTS[i][0] + "; no bookmarks added.");
            }
        }
        BookmarkManager manager = currentProgram.getBookmarkManager();
        int added = 0;
        for (int i = 0; i < POINTS.length; i++) {
            if (manager.getBookmark(addresses[i], "Note", CATEGORY) == null) {
                manager.setBookmark(addresses[i], "Note", CATEGORY, POINTS[i][1]);
                added++;
            }
        }
        println("GBW3 Study: added " + added + " bookmarks. Open Window > Bookmarks and filter category GBW3 Study.");
        println("No bytes, symbols, function definitions, comments or data types changed.");
    }
}
