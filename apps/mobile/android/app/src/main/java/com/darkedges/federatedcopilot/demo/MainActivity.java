package com.darkedges.federatedcopilot.demo;

import com.getcapacitor.BridgeActivity;
import android.os.Bundle;
import android.view.WindowManager;

public class MainActivity extends BridgeActivity {
    @Override public void onCreate(Bundle state) {
        registerPlugin(DevicePresencePlugin.class);
        registerPlugin(MobilePresencePlugin.class);
        registerPlugin(BrowserLoginPlugin.class);
        super.onCreate(state);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
    }
}
