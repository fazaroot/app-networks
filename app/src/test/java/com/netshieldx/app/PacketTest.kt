package com.netshieldx.app

import com.netshieldx.app.vpn.BlocklistManager
import com.netshieldx.app.vpn.Checksum
import com.netshieldx.app.vpn.IpPacket
import com.netshieldx.app.vpn.TcpPacket
import com.netshieldx.app.vpn.UdpPacket
import com.netshieldx.app.vpn.UidMapper
import com.netshieldx.app.vpn.VpnEngine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PacketTest {

    @Test
    fun ipBuildAndParse_roundTrip() {
        val src = byteArrayOf(10, 8, 0, 2)
        val dst = byteArrayOf(8, 8, 8, 8)
        val payload = byteArrayOf(1, 2, 3, 4)
        val packet = IpPacket.build(src, dst, IpPacket.PROTOCOL_UDP, payload)
        val header = IpPacket.parse(packet, packet.size)
        assertNotNull(header)
        assertEquals(4, header!!.version)
        assertEquals(IpPacket.PROTOCOL_UDP, header.protocol)
        assertEquals("10.8.0.2", header.srcAddressString())
        assertEquals("8.8.8.8", header.dstAddressString())
        assertEquals(20 + payload.size, header.totalLength)
    }

    @Test
    fun ipParse_rejectsNonIpv4() {
        val packet = ByteArray(40)
        packet[0] = 0x60.toByte()
        assertNull(IpPacket.parse(packet, packet.size))
    }

    @Test
    fun ipParse_rejectsShortPacket() {
        assertNull(IpPacket.parse(ByteArray(10), 10))
    }

    @Test
    fun ipChecksum_isValid() {
        val src = byteArrayOf(10, 0, 0, 1)
        val dst = byteArrayOf(10, 0, 0, 2)
        val packet = IpPacket.build(src, dst, IpPacket.PROTOCOL_TCP, ByteArray(0))
        // Checksum header yang valid menghasilkan 0 saat dihitung ulang.
        assertEquals(0, Checksum.compute(packet, 0, 20))
    }

    @Test
    fun udpBuildAndParse_roundTrip() {
        val src = byteArrayOf(10, 8, 0, 2)
        val dst = byteArrayOf(1, 1, 1, 1)
        val payload = byteArrayOf(9, 9, 9)
        val udp = UdpPacket.build(src, dst, 12345, 53, payload)
        val header = UdpPacket.parse(udp, 0, udp.size)
        assertNotNull(header)
        assertEquals(12345, header!!.srcPort)
        assertEquals(53, header.dstPort)
        assertEquals(8 + payload.size, header.length)
    }

    @Test
    fun tcpBuildAndParse_roundTrip() {
        val src = byteArrayOf(10, 8, 0, 2)
        val dst = byteArrayOf(93, 184.toByte(), 216.toByte(), 34)
        val tcp = TcpPacket.build(src, dst, 40000, 443, 1000L, 2000L, TcpPacket.FLAG_SYN, mss = 1460)
        val header = TcpPacket.parse(tcp, 0, tcp.size)
        assertNotNull(header)
        assertEquals(40000, header!!.srcPort)
        assertEquals(443, header.dstPort)
        assertEquals(1000L, header.sequenceNumber)
        assertEquals(2000L, header.acknowledgementNumber)
        assertTrue(header.isSyn)
        assertEquals(24, header.dataOffset)
    }

    @Test
    fun tcpFlags_parsed() {
        val src = byteArrayOf(10, 0, 0, 1)
        val dst = byteArrayOf(10, 0, 0, 2)
        val tcp = TcpPacket.build(src, dst, 1, 2, 0L, 0L, TcpPacket.FLAG_FIN or TcpPacket.FLAG_ACK)
        val header = TcpPacket.parse(tcp, 0, tcp.size)!!
        assertTrue(header.isFin)
        assertTrue(header.isAck)
        assertTrue(!header.isSyn)
    }

    @Test
    fun parseAddress_validAndInvalid() {
        assertNotNull(IpPacket.parseAddress("192.168.1.1"))
        assertNull(IpPacket.parseAddress("999.1.1.1"))
        assertNull(IpPacket.parseAddress("not-an-ip"))
        assertNull(IpPacket.parseAddress("1.2.3"))
    }

    @Test
    fun rewriteTransactionId_changesFirstTwoBytes() {
        val response = byteArrayOf(0x00, 0x01, 0x02, 0x03)
        val rewritten = VpnEngine.rewriteTransactionId(response, 0xABCD)
        assertEquals(0xAB.toByte(), rewritten[0])
        assertEquals(0xCD.toByte(), rewritten[1])
        assertEquals(0x02.toByte(), rewritten[2])
    }

    @Test
    fun parseHostsLine_hostsFormat() {
        assertEquals("ads.example.com", BlocklistManager.parseHostsLine("0.0.0.0 ads.example.com"))
        assertEquals("ads.example.com", BlocklistManager.parseHostsLine("127.0.0.1 ads.example.com # komentar"))
        assertEquals("ads.example.com", BlocklistManager.parseHostsLine("ads.example.com"))
        assertNull(BlocklistManager.parseHostsLine("# komentar saja"))
        assertNull(BlocklistManager.parseHostsLine("0.0.0.0 localhost"))
        assertNull(BlocklistManager.parseHostsLine(""))
        assertNull(BlocklistManager.parseHostsLine("0.0.0.0"))
    }

    @Test
    fun parseProcNetLine_extractsPortAndUid() {
        // Format /proc/net/tcp: sl local_address rem_address st ... uid ...
        val line = "  0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000  0 12345 1 00000000 100 0 0 10 0"
        val result = UidMapper.parseProcNetLine(line)
        assertNotNull(result)
        assertEquals(53, result!!.first)
        assertEquals(1000, result.second)
    }
}
