package com.netshieldx.app

import com.netshieldx.app.vpn.DnsPacket
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class DnsPacketTest {

    /** Query DNS standar untuk example.com tipe A. */
    private fun buildQuery(domain: String = "example.com", id: Int = 0x1234): ByteArray {
        val labels = domain.split(".")
        val size = 12 + labels.sumOf { it.length + 1 } + 1 + 4
        val data = ByteArray(size)
        data[0] = (id shr 8).toByte()
        data[1] = id.toByte()
        data[2] = 0x01
        data[3] = 0x00
        data[4] = 0
        data[5] = 1
        var offset = 12
        for (label in labels) {
            data[offset] = label.length.toByte()
            offset++
            label.toByteArray(Charsets.UTF_8).copyInto(data, offset)
            offset += label.length
        }
        data[offset] = 0
        offset++
        data[offset] = 0
        data[offset + 1] = DnsPacket.TYPE_A.toByte()
        data[offset + 2] = 0
        data[offset + 3] = DnsPacket.CLASS_IN.toByte()
        return data
    }

    @Test
    fun parseQuery_extractsNameAndType() {
        val query = DnsPacket.parseQuery(buildQuery(), buildQuery().size)
        assertNotNull(query)
        assertEquals(0x1234, query!!.transactionId)
        assertEquals("example.com", query.firstQuestion?.name)
        assertEquals(DnsPacket.TYPE_A, query.firstQuestion?.type)
    }

    @Test
    fun parseQuery_tooShort_returnsNull() {
        assertNull(DnsPacket.parseQuery(ByteArray(5), 5))
    }

    @Test
    fun parseQuery_noQuestions_returnsNull() {
        val data = ByteArray(12)
        assertNull(DnsPacket.parseQuery(data, data.size))
    }

    @Test
    fun extractQueryName_returnsLowercase() {
        val query = buildQuery("Ads.Example.COM")
        assertEquals("ads.example.com", DnsPacket.extractQueryName(query, query.size))
    }

    @Test
    fun normalizeDomain_trimsDotAndCase() {
        assertEquals("example.com", DnsPacket.normalizeDomain("Example.COM."))
        assertEquals("a.b.example.com", DnsPacket.normalizeDomain("  A.B.Example.com "))
    }

    @Test
    fun buildNxDomainResponse_setsRcode3() {
        val raw = buildQuery()
        val query = DnsPacket.parseQuery(raw, raw.size)!!
        val response = DnsPacket.buildNxDomainResponse(query, raw, raw.size)
        assertEquals(0x1234, ((response[0].toInt() and 0xFF) shl 8) or (response[1].toInt() and 0xFF))
        assertEquals(3, response[3].toInt() and 0x0F)
        assertEquals(0, ((response[6].toInt() and 0xFF) shl 8) or (response[7].toInt() and 0xFF))
    }

    @Test
    fun buildBlockedResponse_containsOneAnswer() {
        val raw = buildQuery()
        val query = DnsPacket.parseQuery(raw, raw.size)!!
        val response = DnsPacket.buildBlockedResponse(query, raw, raw.size)
        val anCount = ((response[6].toInt() and 0xFF) shl 8) or (response[7].toInt() and 0xFF)
        assertEquals(1, anCount)
        assertEquals(0, response[3].toInt() and 0x0F)
    }

    @Test
    fun readName_handlesCompressionPointer() {
        val raw = buildQuery("example.com")
        // Bangun pesan kedua yang memakai pointer ke offset 12.
        val data = ByteArray(raw.size + 2)
        System.arraycopy(raw, 0, data, 0, raw.size)
        data[raw.size] = 0xC0.toByte()
        data[raw.size + 1] = 0x0C.toByte()
        val result = DnsPacket.readName(data, raw.size, data.size)
        assertNotNull(result)
        assertEquals("example.com", result!!.first)
        assertEquals(raw.size + 2, result.second)
    }
}
