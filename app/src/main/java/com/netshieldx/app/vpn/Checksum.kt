package com.netshieldx.app.vpn

/**
 * Checksum Internet (RFC 1071) untuk header IPv4, TCP, dan UDP.
 * Kode murni Kotlin tanpa dependensi Android agar bisa diuji unit.
 */
object Checksum {

    fun compute(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            val word = ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            sum += word
            if (sum and 0xFFFF0000L != 0L) {
                sum = (sum and 0xFFFFL) + (sum shr 16)
            }
            i += 2
        }
        if (i < end) {
            val word = (data[i].toInt() and 0xFF) shl 8
            sum += word
        }
        while (sum shr 16 != 0L) {
            sum = (sum and 0xFFFFL) + (sum shr 16)
        }
        return (sum.inv() and 0xFFFFL).toInt()
    }

    fun computePseudoHeader(
        srcAddr: ByteArray,
        dstAddr: ByteArray,
        protocol: Int,
        payload: ByteArray,
        payloadOffset: Int,
        payloadLength: Int
    ): Int {
        var sum = 0L
        fun addWord(high: Int, low: Int) {
            sum += ((high and 0xFF) shl 8) or (low and 0xFF)
            if (sum and 0xFFFF0000L != 0L) sum = (sum and 0xFFFFL) + (sum shr 16)
        }
        addWord(srcAddr[0].toInt(), srcAddr[1].toInt())
        addWord(srcAddr[2].toInt(), srcAddr[3].toInt())
        addWord(dstAddr[0].toInt(), dstAddr[1].toInt())
        addWord(dstAddr[2].toInt(), dstAddr[3].toInt())
        addWord(0, protocol)
        addWord((payloadLength shr 8) and 0xFF, payloadLength and 0xFF)
        var i = payloadOffset
        val end = payloadOffset + payloadLength
        while (i + 1 < end) {
            addWord(payload[i].toInt(), payload[i + 1].toInt())
            i += 2
        }
        if (i < end) {
            sum += (payload[i].toInt() and 0xFF) shl 8
        }
        while (sum shr 16 != 0L) {
            sum = (sum and 0xFFFFL) + (sum shr 16)
        }
        return (sum.inv() and 0xFFFFL).toInt()
    }
}
