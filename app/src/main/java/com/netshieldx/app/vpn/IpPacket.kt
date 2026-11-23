package com.netshieldx.app.vpn

/**
 * Parser dan pembangun header IPv4 (RFC 791).
 * Hanya IPv4 yang didukung NetShield X. Paket IPv6 tidak diproses
 * dan diteruskan tanpa filtering, dan batasan ini didokumentasikan
 * di README dan di layar Privasi & Keamanan.
 */
data class IpHeader(
    val version: Int,
    val headerLength: Int,
    val totalLength: Int,
    val protocol: Int,
    val srcAddress: ByteArray,
    val dstAddress: ByteArray,
    val payloadOffset: Int
) {
    val isIpv4: Boolean get() = version == 4

    fun srcAddressString(): String = srcAddress.joinToString(".") { (it.toInt() and 0xFF).toString() }
    fun dstAddressString(): String = dstAddress.joinToString(".") { (it.toInt() and 0xFF).toString() }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is IpHeader) return false
        return version == other.version && totalLength == other.totalLength &&
            protocol == other.protocol && srcAddress.contentEquals(other.srcAddress) &&
            dstAddress.contentEquals(other.dstAddress)
    }

    override fun hashCode(): Int {
        var result = version
        result = 31 * result + totalLength
        result = 31 * result + protocol
        result = 31 * result + srcAddress.contentHashCode()
        result = 31 * result + dstAddress.contentHashCode()
        return result
    }
}

object IpPacket {
    const val PROTOCOL_TCP = 6
    const val PROTOCOL_UDP = 17
    const val PROTOCOL_ICMP = 1

    fun parse(data: ByteArray, length: Int): IpHeader? {
        if (length < 20) return null
        val version = (data[0].toInt() shr 4) and 0xF
        if (version != 4) return null
        val headerLength = (data[0].toInt() and 0xF) * 4
        if (headerLength < 20 || length < headerLength) return null
        val totalLength = ((data[2].toInt() and 0xFF) shl 8) or (data[3].toInt() and 0xFF)
        if (totalLength < headerLength || totalLength > length) return null
        val protocol = data[9].toInt() and 0xFF
        val src = data.copyOfRange(12, 16)
        val dst = data.copyOfRange(16, 20)
        return IpHeader(version, headerLength, totalLength, protocol, src, dst, headerLength)
    }

    /**
     * Bangun paket IPv4 baru dari payload transport (TCP/UDP).
     * Checksum header dihitung otomatis.
     */
    fun build(
        srcAddress: ByteArray,
        dstAddress: ByteArray,
        protocol: Int,
        payload: ByteArray,
        payloadLength: Int = payload.size
    ): ByteArray {
        val totalLength = 20 + payloadLength
        val packet = ByteArray(totalLength)
        packet[0] = 0x45.toByte()
        packet[1] = 0
        packet[2] = (totalLength shr 8).toByte()
        packet[3] = totalLength.toByte()
        packet[4] = 0
        packet[5] = 0
        packet[6] = 0x40
        packet[7] = 0
        packet[8] = 64
        packet[9] = protocol.toByte()
        packet[10] = 0
        packet[11] = 0
        System.arraycopy(srcAddress, 0, packet, 12, 4)
        System.arraycopy(dstAddress, 0, packet, 16, 4)
        val checksum = Checksum.compute(packet, 0, 20)
        packet[10] = (checksum shr 8).toByte()
        packet[11] = checksum.toByte()
        System.arraycopy(payload, 0, packet, 20, payloadLength)
        return packet
    }

    fun parseAddress(text: String): ByteArray? {
        val parts = text.split(".")
        if (parts.size != 4) return null
        val out = ByteArray(4)
        for (i in parts.indices) {
            val value = parts[i].toIntOrNull() ?: return null
            if (value !in 0..255) return null
            out[i] = value.toByte()
        }
        return out
    }
}
