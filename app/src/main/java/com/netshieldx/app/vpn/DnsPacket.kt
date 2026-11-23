package com.netshieldx.app.vpn

/**
 * Parser dan pembangun pesan DNS (RFC 1035).
 * Mendukung query A dan AAAA, termasuk nama terkompresi (pointer).
 * Kode murni Kotlin agar bisa diuji unit tanpa framework Android.
 */
data class DnsQuestion(
    val name: String,
    val type: Int,
    val clazz: Int
)

data class DnsQuery(
    val transactionId: Int,
    val flags: Int,
    val questions: List<DnsQuestion>
) {
    val firstQuestion: DnsQuestion? get() = questions.firstOrNull()
}

object DnsPacket {
    const val TYPE_A = 1
    const val TYPE_AAAA = 28
    const val CLASS_IN = 1

    const val RCODE_NO_ERROR = 0
    const val RCODE_NAME_ERROR = 3

    fun parseQuery(data: ByteArray, length: Int): DnsQuery? {
        if (length < 12) return null
        val transactionId = ((data[0].toInt() and 0xFF) shl 8) or (data[1].toInt() and 0xFF)
        val flags = ((data[2].toInt() and 0xFF) shl 8) or (data[3].toInt() and 0xFF)
        val qdCount = ((data[4].toInt() and 0xFF) shl 8) or (data[5].toInt() and 0xFF)
        if (qdCount < 1) return null
        var offset = 12
        val questions = mutableListOf<DnsQuestion>()
        repeat(qdCount) {
            val nameResult = readName(data, offset, length) ?: return null
            offset = nameResult.second
            if (offset + 4 > length) return null
            val type = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
            val clazz = ((data[offset + 2].toInt() and 0xFF) shl 8) or (data[offset + 3].toInt() and 0xFF)
            offset += 4
            questions.add(DnsQuestion(nameResult.first, type, clazz))
        }
        return DnsQuery(transactionId, flags, questions)
    }

    /**
     * Baca nama domain dengan dukungan pointer kompresi.
     * Mengembalikan nama dan offset setelah nama (atau setelah pointer).
     */
    fun readName(data: ByteArray, startOffset: Int, length: Int): Pair<String, Int>? {
        val labels = mutableListOf<String>()
        var offset = startOffset
        var nextOffset = -1
        var jumps = 0
        while (offset < length) {
            val len = data[offset].toInt() and 0xFF
            if (len == 0) {
                if (nextOffset == -1) nextOffset = offset + 1
                break
            }
            if (len and 0xC0 == 0xC0) {
                if (offset + 1 >= length) return null
                val pointer = ((len and 0x3F) shl 8) or (data[offset + 1].toInt() and 0xFF)
                if (nextOffset == -1) nextOffset = offset + 2
                if (++jumps > 10 || pointer >= length) return null
                offset = pointer
                continue
            }
            if (len > 63 || offset + 1 + len > length) return null
            val label = String(data, offset + 1, len, Charsets.UTF_8)
            labels.add(label)
            offset += 1 + len
        }
        if (nextOffset == -1) return null
        return labels.joinToString(".") to nextOffset
    }

    /** Bangun respons NXDOMAIN untuk query yang diblokir. */
    fun buildNxDomainResponse(query: DnsQuery, rawQuery: ByteArray, queryLength: Int): ByteArray {
        val response = ByteArray(queryLength)
        System.arraycopy(rawQuery, 0, response, 0, queryLength)
        response[2] = 0x81.toByte()
        response[3] = (0x80 or RCODE_NAME_ERROR).toByte()
        response[6] = 0
        response[7] = 0
        response[8] = 0
        response[9] = 0
        response[10] = 0
        response[11] = 0
        return response
    }

    /** Bangun respons dengan satu jawaban A (0.0.0.0) untuk query yang diblokir. */
    fun buildBlockedResponse(query: DnsQuery, rawQuery: ByteArray, queryLength: Int): ByteArray {
        val question = query.firstQuestion ?: return buildNxDomainResponse(query, rawQuery, queryLength)
        val answer = ByteArray(16)
        answer[0] = 0xC0.toByte()
        answer[1] = 0x0C.toByte()
        answer[2] = 0
        answer[3] = TYPE_A.toByte()
        answer[4] = 0
        answer[5] = CLASS_IN.toByte()
        answer[6] = 0
        answer[7] = 0
        answer[8] = 0
        answer[9] = 60
        answer[10] = 0
        answer[11] = 4
        answer[12] = 0
        answer[13] = 0
        answer[14] = 0
        answer[15] = 0
        val response = ByteArray(queryLength + answer.size)
        System.arraycopy(rawQuery, 0, response, 0, queryLength)
        System.arraycopy(answer, 0, response, queryLength, answer.size)
        response[2] = 0x81.toByte()
        response[3] = (0x80 or RCODE_NO_ERROR).toByte()
        response[6] = 0
        response[7] = 1
        response[8] = 0
        response[9] = 0
        response[10] = 0
        response[11] = 0
        return response
    }

    /** Ekstrak nama domain dari query mentah, atau null jika tidak bisa diparse. */
    fun extractQueryName(data: ByteArray, length: Int): String? {
        return parseQuery(data, length)?.firstQuestion?.name?.lowercase()
    }

    /** Normalisasi domain: huruf kecil, tanpa titik akhir. */
    fun normalizeDomain(domain: String): String {
        return domain.lowercase().trim().trimEnd('.')
    }
}
