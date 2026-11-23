package com.netshieldx.app.vpn

/**
 * Cache DNS sederhana dengan batas ukuran dan TTL.
 * Hanya menyimpan respons DNS mentah (bukan payload sensitif).
 * Menggunakan LRU berdasarkan urutan akses.
 */
class DnsCache(private val maxEntries: Int = 512) {

    private data class Entry(
        val response: ByteArray,
        val expiresAtMs: Long
    )

    private val cache = object : LinkedHashMap<String, Entry>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Entry>?): Boolean {
            return size > maxEntries
        }
    }

    @Synchronized
    fun get(key: String, nowMs: Long = System.currentTimeMillis()): ByteArray? {
        val entry = cache[key] ?: return null
        if (nowMs >= entry.expiresAtMs) {
            cache.remove(key)
            return null
        }
        return entry.response.copyOf()
    }

    @Synchronized
    fun put(key: String, response: ByteArray, ttlSeconds: Int, nowMs: Long = System.currentTimeMillis()) {
        val ttl = ttlSeconds.coerceIn(10, 3600)
        cache[key] = Entry(response.copyOf(), nowMs + ttl * 1000L)
    }

    @Synchronized
    fun clear() {
        cache.clear()
    }

    @Synchronized
    fun size(): Int = cache.size

    companion object {
        /** Kunci cache: nama domain lowercase + tipe query. */
        fun key(domain: String, type: Int): String {
            return DnsPacket.normalizeDomain(domain) + "|" + type
        }
    }
}
