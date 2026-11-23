package com.netshieldx.app.device

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.TrafficStats
import android.os.Build
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow

/** Statistik trafik perangkat dari TrafficStats (data aktual sistem). */
data class TrafficSnapshot(
    val totalRxBytes: Long,
    val totalTxBytes: Long,
    val rxRateBytesPerSec: Long,
    val txRateBytesPerSec: Long,
    val timestampMs: Long
) {
    companion object {
        fun unsupported(): TrafficSnapshot = TrafficSnapshot(-1, -1, 0, 0, System.currentTimeMillis())
    }
}

/** Informasi aplikasi terpasang untuk layar Firewall. */
data class InstalledAppInfo(
    val packageName: String,
    val label: String,
    val isSystem: Boolean,
    val uid: Int
)

object TrafficMonitor {

    fun readTotals(): TrafficSnapshot {
        val rx = TrafficStats.getTotalRxBytes()
        val tx = TrafficStats.getTotalTxBytes()
        if (rx == TrafficStats.UNSUPPORTED.toLong() && tx == TrafficStats.UNSUPPORTED.toLong()) {
            return TrafficSnapshot.unsupported()
        }
        return TrafficSnapshot(rx.coerceAtLeast(0), tx.coerceAtLeast(0), 0, 0, System.currentTimeMillis())
    }

    fun uidRxBytes(uid: Int): Long {
        val value = TrafficStats.getUidRxBytes(uid)
        return if (value == TrafficStats.UNSUPPORTED.toLong()) -1 else value
    }

    fun uidTxBytes(uid: Int): Long {
        val value = TrafficStats.getUidTxBytes(uid)
        return if (value == TrafficStats.UNSUPPORTED.toLong()) -1 else value
    }

    /** Sampling kecepatan: membandingkan dua pembacaan dengan jeda intervalMs. */
    fun sampleRates(intervalMs: Long = 1000L): Flow<TrafficSnapshot> = flow {
        var previous = readTotals()
        while (true) {
            kotlinx.coroutines.delay(intervalMs)
            val current = readTotals()
            if (previous.totalRxBytes < 0 || current.totalRxBytes < 0) {
                emit(current)
            } else {
                val seconds = intervalMs / 1000.0
                val rxRate = ((current.totalRxBytes - previous.totalRxBytes).coerceAtLeast(0) / seconds).toLong()
                val txRate = ((current.totalTxBytes - previous.totalTxBytes).coerceAtLeast(0) / seconds).toLong()
                emit(current.copy(rxRateBytesPerSec = rxRate, txRateBytesPerSec = txRate))
            }
            previous = current
        }
    }

    fun formatBytes(bytes: Long): String {
        if (bytes < 0) return "Tidak diketahui"
        if (bytes < 1024) return "$bytes B"
        val kb = bytes / 1024.0
        if (kb < 1024) return "%.1f KB".format(kb)
        val mb = kb / 1024.0
        if (mb < 1024) return "%.1f MB".format(mb)
        val gb = mb / 1024.0
        return "%.2f GB".format(gb)
    }

    fun formatRate(bytesPerSec: Long): String {
        if (bytesPerSec < 0) return "Tidak diketahui"
        if (bytesPerSec < 1024) return "$bytesPerSec B/dtk"
        val kb = bytesPerSec / 1024.0
        if (kb < 1024) return "%.1f KB/dtk".format(kb)
        return "%.1f MB/dtk".format(kb / 1024.0)
    }
}

object AppInfoProvider {

    fun getInstalledApps(context: Context): List<InstalledAppInfo> {
        val pm = context.packageManager
        val apps = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledApplications(0)
        }
        return apps.mapNotNull { info ->
            val label = runCatching { pm.getApplicationLabel(info).toString() }.getOrNull()
                ?: info.packageName
            InstalledAppInfo(
                packageName = info.packageName,
                label = label,
                isSystem = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
                uid = info.uid
            )
        }.sortedWith(compareBy({ it.isSystem }, { it.label.lowercase() }))
    }

    /** Petakan UID ke package name lewat PackageManager. Null jika tidak bisa dipetakan. */
    fun getPackagesForUid(context: Context, uid: Int): List<String> {
        if (uid < 0) return emptyList()
        return try {
            context.packageManager.getPackagesForUid(uid)?.toList() ?: emptyList()
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun getUidForPackage(context: Context, packageName: String): Int {
        return try {
            context.packageManager.getApplicationInfo(packageName, 0).uid
        } catch (_: Exception) {
            -1
        }
    }
}
