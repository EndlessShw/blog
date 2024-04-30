import java.io.IOException;

/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2023/5/15 15:18
 */
public class Evil {
    public Evil() throws IOException {
        Runtime.getRuntime().exec("calc");
    }
}
