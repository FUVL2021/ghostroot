package com.fuxi.ghostroot;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.os.CountDownTimer;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/**
 * #9 免责声明页（强制停留 10 秒）。
 *
 * 设计要点：
 *   · **强制停留 10 秒**后才允许点「我已阅读并同意」——用 CountDownTimer
 *     每 1s 刷新按钮文案（"我已阅读并同意（还剩 Ns）"），倒计时中按钮 disabled。
 *   · 全部 UI 用纯 Java 构建（本工程无 aapt2/Gradle，不能重编资源表）。
 *   · 「不同意」直接 finish()，停在空界面，不让进主功能。
 *   · 本页是 LAUNCHER 入口，同意后才 startActivity(MainActivity)。
 */
public class DisclaimerActivity extends Activity {

    /** 强制停留秒数。 */
    private static final int WAIT_SEC = 10;

    private Button agreeBtn;
    private CountDownTimer timer;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);

        int pad = (int) (getResources().getDisplayMetrics().density * 16);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(0xFF0D1117);
        root.setPadding(pad, pad, pad, pad);

        // ---- 标题 ----
        TextView title = new TextView(this);
        title.setText("⚠️  使用前必读");
        title.setTextColor(0xFFF44336);
        title.setTextSize(22);
        root.addView(title);

        // ---- 正文（可滚动）----
        ScrollView sc = new ScrollView(this);
        TextView body = new TextView(this);
        body.setTextColor(0xFFC9D1D9);
        body.setTextSize(14);
        body.setPadding(0, pad, 0, pad);
        body.setText(
                "本工具仅用于【且仅限于】你自己拥有的设备的\n"
              + "安全研究与学习。\n"
              + "\n"
              + "【风险提示】\n"
              + "· 本工具通过内核漏洞获取 root 权限，属高危操作；\n"
              + "· 唯一的风险是：**可能造成内核卡死（黑屏 / 无响应）**，\n"
              + "  此时**长按电源键强制重启即可恢复**；\n"
              + "· 本工具**不改动任何分区、不刷写 boot / 固件、不格式化数据**，\n"
              + "  因此**不会造成系统损坏或数据丢失**。\n"
              + "\n"
              + "【注意事项】\n"
              + "1. 请不要中途退出软件，否则可能导致提权失败；\n"
              + "2. 如果 30 秒内没有提权完成，基本可以判定为失败\n"
              + "   （可能是判断逻辑没写好），重启后重试；\n"
              + "3. 保持屏幕常亮、把本 App 留在前台；\n"
              + "4. 若日志出现[-] atomic credential transaction verification failed[-] root chain stopped with one-shot PI state alive; reboot before retrying等失败特征，\n"
              + "   请**先重启设备**再重试，不要连续硬跑。\n"
              + "\n"
              + "【免责声明】\n"
              + "使用本工具即表示你已知悉上述风险并自行承担全部后果。\n"
              + "请勿将本工具用于任何非授权设备。\n"
              + "\n"
              + "本工具**完全免费**，若你是付费获得的，恭喜你被骗了。\n"
              + "作者 QQ：2084089509\n"
              + "（反馈 / 交流可用，不提供任何收费服务）\n"
        );
        sc.addView(body);
        root.addView(sc, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        // ---- 同意按钮（倒计时中禁用）----
        agreeBtn = new Button(this);
        agreeBtn.setText("我已阅读并同意（" + WAIT_SEC + "s）");
        agreeBtn.setEnabled(false);
        agreeBtn.setTextSize(16);
        agreeBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                if (timer != null) timer.cancel();
                try {
                    startActivity(new Intent(DisclaimerActivity.this, MainActivity.class));
                } catch (Throwable ignored) {}
                finish();
            }
        });
        root.addView(agreeBtn, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        // ---- 不同意 ----
        Button rejectBtn = new Button(this);
        rejectBtn.setText("不同意（退出）");
        rejectBtn.setTextSize(14);
        rejectBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                if (timer != null) timer.cancel();
                finish();
            }
        });
        root.addView(rejectBtn, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        setContentView(root);

        // ---- 倒计时 ----
        timer = new CountDownTimer(WAIT_SEC * 1000L, 1000L) {
            @Override public void onTick(long msLeft) {
                long s = (msLeft + 999) / 1000;
                agreeBtn.setText("我已阅读并同意（" + s + "s）");
            }
            @Override public void onFinish() {
                agreeBtn.setText("我已阅读并同意");
                agreeBtn.setEnabled(true);
                agreeBtn.setTextColor(Color.WHITE);
            }
        }.start();
    }

    @Override
    protected void onDestroy() {
        if (timer != null) { timer.cancel(); timer = null; }
        super.onDestroy();
    }

    /** 禁止返回键跳过（直接退出，不留给"按返回"绕过倒计时的路）。 */
    @Override
    public void onBackPressed() {
        if (timer != null) timer.cancel();
        finish();
    }
}