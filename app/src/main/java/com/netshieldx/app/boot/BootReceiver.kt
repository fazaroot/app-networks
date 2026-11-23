package com.netshieldx.app.boot

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import com.netshieldx.app.data.db.AppDatabase
import com.netshieldx.app.vpn.NetShieldVpnService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * Memulai perlindungan saat boot hanya jika pengguna mengaktifkannya
 * di Pengaturan dan persetujuan VPN sudah pernah diberikan.
 * VpnService.prepare() mengembalikan null bila sudah disetujui
 * sebelumnya, sehingga tidak ada permintaan diam-diam.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val pending = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val db = AppDatabase.getInstance(context)
                val settings = db.userSettingsDao().getSettingsOnce()
                if (settings?.startOnBoot == true) {
                    if (VpnService.prepare(context) == null) {
                        val serviceIntent = Intent(context, NetShieldVpnService::class.java)
                        serviceIntent.action = NetShieldVpnService.ACTION_START
                        context.startForegroundService(serviceIntent)
                    }
                }
            } catch (_: Exception) {
            } finally {
                pending.finish()
            }
        }
    }
}
