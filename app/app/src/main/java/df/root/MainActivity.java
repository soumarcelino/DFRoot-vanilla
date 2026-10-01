package df.root;

import android.app.Activity;
import android.os.Bundle;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.graphics.Color;

import java.util.concurrent.Executors;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public final class MainActivity extends Activity implements IReporter {
    private TextView logs;
    private Button run;
    private ScrollView scroll;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        int padding = (int) (16 * getResources().getDisplayMetrics().density);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(padding, padding, padding, padding);
        layout.setOnApplyWindowInsetsListener((view, insets) -> {
            view.setPadding(
                    padding + insets.getSystemWindowInsetLeft(),
                    padding + insets.getSystemWindowInsetTop(),
                    padding + insets.getSystemWindowInsetRight(),
                    padding + insets.getSystemWindowInsetBottom());
            return insets;
        });

        logs = new TextView(this);
        logs.setTextIsSelectable(true);
        logs.setMovementMethod(new ScrollingMovementMethod());
        logs.setTextSize(13);
        logs.setPadding(0, 0, 0, padding / 2);
        scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.addView(logs);
        layout.addView(scroll, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));

        run = new Button(this);
        run.setText("Run");
        run.setAllCaps(false);
        run.setTextColor(Color.WHITE);
        run.setTextSize(17);
        run.setBackgroundResource(R.drawable.run_button);
        run.setMinHeight((int) (56 * getResources().getDisplayMetrics().density));
        LinearLayout.LayoutParams buttonParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                (int) (56 * getResources().getDisplayMetrics().density));
        buttonParams.topMargin = padding;
        layout.addView(run, buttonParams);
        setContentView(layout);

        run.setOnClickListener(view -> {
            run.setEnabled(false);
            logs.setText("");
            Executors.newSingleThreadExecutor().execute(() -> {
                report("[APP] stage=session status=started\n");
                try {
                    int result = ExploitRunner.run(this, this);
                    report("[RESULT] status=" + (result == 0 ? "success" : "failed")
                            + " exit_code=" + result + "\n");
                } catch (Throwable error) {
                    StringWriter trace = new StringWriter();
                    error.printStackTrace(new PrintWriter(trace));
                    report("[RESULT] status=exception type=" + error.getClass().getName()
                            + " message=" + error.getMessage() + "\n" + trace + "\n");
                }
                runOnUiThread(() -> run.setEnabled(true));
            });
        });
    }

    @Override public void report(String message) {
        String time = new SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(new Date());
        StringBuilder formatted = new StringBuilder();
        for (String line : message.split("\\n", -1)) {
            if (!line.isEmpty()) formatted.append(time).append(" ").append(line).append("\n");
        }
        Log.i("DFRoot", formatted.toString().trim());
        runOnUiThread(() -> {
            logs.append(formatted);
            scroll.post(() -> scroll.fullScroll(ScrollView.FOCUS_DOWN));
        });
    }
}
