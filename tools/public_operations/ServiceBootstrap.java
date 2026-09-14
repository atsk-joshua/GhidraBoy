import ghidra.*;
import java.util.Arrays;
/** Load the probe only after the stock runtime establishes its classpath. */
public class ServiceBootstrap implements GhidraLaunchable {
  public void launch(GhidraApplicationLayout layout,String[] args)throws Exception {
    ((GhidraClassLoader)ClassLoader.getSystemClassLoader()).addPath(args[0]);
    ((GhidraLaunchable)Class.forName("ServiceProbe",true,ClassLoader.getSystemClassLoader()).getConstructor().newInstance()).launch(layout,Arrays.copyOfRange(args,1,args.length));
  }
}
