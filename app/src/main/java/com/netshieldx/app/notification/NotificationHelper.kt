package com.netshieldx.app.notification

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import com.netshieldx.app.MainActivity
import com.netshieldx.app.R

object NotificationHelper {
    const val VPN_CHANNEL_ID = "netshield_vpn"
    const val THREAT_CHANNEL_ID = "netshield_threat"
    const val VPN_NOTIFICATION_ID = 1
    const val THREAT_NOTIFICATION_BASE_ID = 100

    fun createChannels(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.createNotificationChannel(
            NotificationChannel(
                VPN_CHANNEL_ID,
                context.getString(R.string.vpn_channel_name),
                NotificationManager.IMPORTANCE_LOW
            ).apply { description = context.getString(R.string.vpn_channel_desc) }
        )
        manager.createNotificationChannel(
            NotificationChannel(
                THREAT_CHANNEL_ID,
                context.getString(R.string.threat_channel_name),
                NotificationManager.IMPORTANCE_HIGH
            ).apply { description = context.getString(R.string.threat_channel_desc) }
        )
    }

    fun buildVpnNotification(context: Context, blockedCount: Long, connections: Long): Notification {
        val intent = Intent(context, MainActivity::class.java)
        val pending = PendingIntent.getActivity(
            context, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(context, VPN_CHANNEL_ID)
            .setContentTitle("NetShield X aktif")
            .setContentText("Melindungi jaringan lokal. Diblokir: $blockedCount domain, diperiksa: $connections koneksi.")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pending)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()
    }

    fun showThreatNotification(context: Context, domain: String, level: String, reason: String) {
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val intent = Intent(context, MainActivity::class.java)
        val pending = PendingIntent.getActivity(
            context, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val notification = NotificationCompat.Builder(context, THREAT_CHANNEL_ID)
            .setContentTitle("Ancaman terdeteksi ($level): $domain")
            .setContentText(reason)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentIntent(pending)
            .setAutoCancel(true)
            .build()
        manager.notify(THREAT_NOTIFICATION_BASE_ID + (domain.hashCode() and 0xFF), notification)
    }

    fun showAlertNotification(context: Context, packageName: String, dstAddress: String) {
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val intent = Intent(context, MainActivity::class.java)
        val pending = PendingIntent.getActivity(
            context, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val notification = NotificationCompat.Builder(context, THREAT_CHANNEL_ID)
            .setContentTitle("Aplikasi dalam mode Peringatan: $packageName")
            .setContentText("Aplikasi terhubung ke $dstAddress.")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentIntent(pending)
            .setAutoCancel(true)
            .build()
        manager.notify(THREAT_NOTIFICATION_BASE_ID + 500 + (packageName.hashCode() and 0xFF), notification)
    }
}
