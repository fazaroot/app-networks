package com.netshieldx.app.vpn

import java.io.File

/**
 * Pemetaan port lokal ke UID aplikasi dengan membaca /proc/net.
 *
 * VpnService tidak memberi tahu UID pemilik tiap paket. Teknik yang
 * dipakai aplikasi firewall lokal (misalnya NetGuard) adalah mencocokkan
 * port sumber paket dengan soket yang tercatat di /proc/net/tcp,
 * /proc/net/udp, dan varian IPv6-nya, yang mencantumkan UID pemilik.
 *
 * Keterbatasan yang jujur:
 * - Pemetaan bersifat best-effort dan bisa gagal untuk koneksi yang
 *   sangat singkat (soket sudah tertutup saat /proc dibaca).
 * - Untuk UDP tanpa koneksi, entri bisa tidak ada.
 * - Jika pemetaan gagal, UID dilaporkan -1 dan aplikasi ditampilkan
 *   sebagai unknown, tidak pernah dikarang.
 */
class UidMapper(private val refreshIntervalMs: Long = 3_000L) {

    private var lastRefreshMs = 0L
    private var tcpMap: Map<Int, Int> = emptyMap()
    private var udpMap: Map<Int, Int> = emptyMap()

    @Synchronized
    fun getUidForPort(protocol: Int, localPort: Int): Int {
        refreshIfNeeded()
        val map = if (protocol == IpPacket.PROTOCOL_UDP) udpMap else tcpMap
        return map[localPort] ?: -1
    }

    @Synchronized
    fun refreshIfNeeded(nowMs: Long = System.currentTimeMillis()) {
        if (nowMs - lastRefreshMs < refreshIntervalMs && lastRefreshMs != 0L) return
        lastRefreshMs = nowMs
        tcpMap = readProcNet(listOf("/proc/net/tcp", "/proc/net/tcp6"))
        udpMap = readProcNet(listOf("/proc/net/udp", "/proc/net/udp6"))
    }

    private fun readProcNet(paths: List<String>): Map<Int, Int> {
        val result = mutableMapOf<Int, Int>()
        for (path in paths) {
            try {
                File(path).useLines { lines ->
                    var first = true
                    for (line in lines) {
                        if (first) {
                            first = false
                            continue
                        }
                        parseProcNetLine(line)?.let { (port, uid) ->
                            result[port] = uid
                        }
                    }
                }
            } catch (_: Exception) {
            }
        }
        return result
    }

    companion object {
        /**
         * Parse satu baris file /proc/net menjadi pasangan (port lokal, uid).
         * Kolom: sl, local_address, rem_address, st, tx_queue:rx_queue,
         * tr:tm->when, retrnsmt, uid, timeout, inode.
         */
        fun parseProcNetLine(line: String): Pair<Int, Int>? {
            val parts = line.trim().split(Regex("\\s+"))
            if (parts.size < 8) return null
            val local = parts[1]
            val portHex = local.substringAfter(":", "")
            val port = portHex.toIntOrNull(16) ?: return null
            val uid = parts[7].toIntOrNull() ?: return null
            return port to uid
        }
    }
}
