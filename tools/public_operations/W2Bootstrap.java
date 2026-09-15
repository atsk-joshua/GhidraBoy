import ghidra.*;
import java.util.Arrays;
public class W2Bootstrap implements GhidraLaunchable {
 public void launch(GhidraApplicationLayout layout,String[] args)throws Exception {
  ((GhidraClassLoader)ClassLoader.getSystemClassLoader()).addPath(args[0]);
  ((GhidraLaunchable)Class.forName("W2NormalProbe",true,ClassLoader.getSystemClassLoader()).getConstructor().newInstance()).launch(layout,Arrays.copyOfRange(args,1,args.length));
 }
}
