package com.zapia.debugbrowser;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.VideoView;

public class SplashActivity extends Activity {
    private boolean opened;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        requestWindowFeature(Window.FEATURE_NO_TITLE);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN, WindowManager.LayoutParams.FLAG_FULLSCREEN);

        VideoView video = new VideoView(this);
        video.setBackgroundColor(0xFF14171D);
        video.setOnPreparedListener(player -> {
            player.setLooping(false);
            video.start();
        });
        video.setOnCompletionListener(player -> openBrowser());
        video.setOnErrorListener((player, what, extra) -> {
            openBrowser();
            return true;
        });
        video.setOnClickListener(view -> openBrowser());
        video.setVideoURI(Uri.parse("android.resource://" + getPackageName() + "/" + R.raw.browserdebug_startup));
        setContentView(video);
    }

    private void openBrowser() {
        if (opened) return;
        opened = true;
        startActivity(new Intent(this, MainActivity.class));
        finish();
    }

    @Override public void onBackPressed() {
        openBrowser();
    }
}
