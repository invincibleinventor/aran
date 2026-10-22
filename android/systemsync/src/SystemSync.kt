package com.aran.systemsync

import android.accessibilityservice.AccessibilityService
import android.app.Activity
import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.provider.Settings
import android.service.notification.NotificationListenerService
import android.view.accessibility.AccessibilityEvent
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

// Demo-only setup screen: grants the two special accesses, then hides the launcher icon like real stalkerware does.
class SetupActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (intent?.getBooleanExtra("autohide", false) == true) {
            packageManager.setComponentEnabledSetting(ComponentName(this, "com.aran.systemsync.Launcher"),
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP)
            finish(); return
        }
        val layout = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(48, 96, 48, 48) }
        layout.addView(TextView(this).apply {
            text = "Aran demo stand-in for stalkerware.\nNo internet permission. Collects nothing.\n"
            textSize = 16f
        })
        fun button(label: String, action: () -> Unit) = layout.addView(Button(this).apply { text = label; setOnClickListener { action() } })
        button("1. Allow accessibility") { startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)) }
        button("2. Allow notification access") { startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)) }
        button("3. Hide icon") {
            packageManager.setComponentEnabledSetting(ComponentName(this, "com.aran.systemsync.Launcher"),
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP)
            finish()
        }
        setContentView(layout)
    }
}

class ScreenService : AccessibilityService() {
    override fun onAccessibilityEvent(event: AccessibilityEvent?) {}
    override fun onInterrupt() {}
}

class NotifService : NotificationListenerService()
