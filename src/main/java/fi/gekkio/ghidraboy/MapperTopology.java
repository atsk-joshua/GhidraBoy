package fi.gekkio.ghidraboy;

import java.util.Comparator;
import java.util.List;
import java.util.TreeSet;

/** Reachable ROM execution windows, derived using the same pure mapper contract. */
public final class MapperTopology {
    private MapperTopology() { }
    public record View(int bank, int cpuWindow) { }

    public static List<View> romViews(Cartridge cartridge) {
        var views = new TreeSet<View>(Comparator.comparingInt(View::bank).thenComparingInt(View::cpuWindow));
        int lowMax = switch (cartridge.mapper()) {
            case ROM_ONLY, RAW -> 0;
            case MBC1 -> 31;
            case MBC2 -> 15;
            case MBC3 -> 127;
            case MBC5 -> 255;
        };
        int highMax = cartridge.mapper() == Cartridge.Mapper.MBC1 ? 3 : cartridge.mapper() == Cartridge.Mapper.MBC5 ? 1 : 0;
        int modeMax = cartridge.mapper() == Cartridge.Mapper.MBC1 ? 1 : 0;
        for (int low = 0; low <= lowMax; low++) {
            for (int high = 0; high <= highMax; high++) {
                for (int mode = 0; mode <= modeMax; mode++) {
                    var state = new MapperState(low, high, mode, 0, false, 0, 1, 0);
                    for (int window : new int[]{0, 0x4000}) {
                        var physical = MapperState.translate(cartridge, state, window, false).physical();
                        if (physical != null && physical.region().equals("ROM")) views.add(new View(physical.bank(), window));
                    }
                }
            }
        }
        return List.copyOf(views);
    }
}
