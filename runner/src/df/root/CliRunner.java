package df.root;

import android.content.Context;
import android.os.Looper;

import java.lang.reflect.Method;

public final class CliRunner {
    private static Context systemContext() throws Exception {
        if (Looper.myLooper() == null) Looper.prepare();
        Class<?> activityThread = Class.forName("android.app.ActivityThread");
        Method systemMain = activityThread.getDeclaredMethod("systemMain");
        Object thread = systemMain.invoke(null);
        Method getSystemContext = activityThread.getDeclaredMethod("getSystemContext");
        return (Context) getSystemContext.invoke(thread);
    }

    public static void main(String[] args) {
        boolean softReboot = args.length > 0 && "--soft-reboot".equals(args[0]);
        try {
            int rc = ExploitRunner.run(systemContext(), System.out::print, softReboot);
            System.out.println("DFROOT_EXIT=" + rc);
            System.exit(rc);
        } catch (Throwable error) {
            error.printStackTrace(System.err);
            System.exit(100);
        }
    }
}
