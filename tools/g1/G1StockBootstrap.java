import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.GhidraClassLoader;
import java.util.Arrays;

/** Add only driver classes after Ghidra builds its supported runtime classpath. */
public class G1StockBootstrap implements GhidraLaunchable {
  @Override public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {
    var loader = (GhidraClassLoader) ClassLoader.getSystemClassLoader();
    loader.addPath(args[0]);
    var driver = (GhidraLaunchable) Class.forName("G1StockNormalLaunch", true, loader).getConstructor().newInstance();
    driver.launch(layout, Arrays.copyOfRange(args, 1, args.length));
  }
}
