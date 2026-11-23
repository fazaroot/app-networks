package com.netshieldx.app.vpn

/** Parser dan pembangun header UDP (RFC 768). */
data class UdpHeader(
    val srcPort: Int,
    val dstPort: Int,
    val length: Int,
    val payloadOffset: Int
)

object UdpPacket {
    const val HEADER_LENGTH = 8

    fun parse(data: ByteArray, offset: Int, length: Int): UdpHeader? {
        if (length - offset < HEADER_LENGTH) return null
        val srcPort = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
        val dstPort = ((data[offset + 2].toInt() and 0xFF) shl 8) or (data[offset + 3].toInt() and 0xFF)
        val udpLength = ((data[offset + 4].toInt() and 0xFF) shl 8) or (data[offset + 5].toInt() and 0xFF)
        if (udpLength < HEADER_LENGTH || offset + udpLength > length) return null
        return UdpHeader(srcPort, dstPort, udpLength, offset + HEADER_LENGTH)
    }

    fun build(
        srcAddress: ByteArray,
        dstAddress: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray,
        payloadLength: Int = payload.size
    ): ByteArray {
        val totalLength = HEADER_LENGTH + payloadLength
        val packet = ByteArray(totalLength)
        packet[0] = (srcPort shr 8).toByte()
        packet[1] = srcPort.toByte()
        packet[2] = (dstPort shr 8).toByte()
        packet[3] = dstPort.toByte()
        packet[4] = (totalLength shr 8).toByte()
        packet[5] = totalLength.toByte()
        packet[6] = 0
        packet[7] = 0
        System.arraycopy(payload, 0, packet, HEADER_LENGTH, payloadLength)
        val checksum = Checksum.computePseudoHeader(
            srcAddress, dstAddress, IpPacket.PROTOCOL_UDP, packet, 0, totalLength
        )
        packet[6] = (checksum shr 8).toByte()
        packet[7] = checksum.toByte()
        return packet
    }
}

/** Parser dan pembangun header TCP (RFC 793). */
data class TcpHeader(
    val srcPort: Int,
    val dstPort: Int,
    val sequenceNumber: Long,
    val acknowledgementNumber: Long,
    val dataOffset: Int,
    val flags: Int,
    val windowSize: Int,
    val payloadOffset: Int
) {
    val isSyn: Boolean get() = flags and 0x02 != 0
    val isAck: Boolean get() = flags and 0x10 != 0
    val isFin: Boolean get() = flags and 0x01 != 0
    val isRst: Boolean get() = flags and 0x04 != 0
    val isPsh: Boolean get() = flags and 0x08 != 0
}

object TcpPacket {
    const val FLAG_FIN = 0x01
    const val FLAG_SYN = 0x02
    const val FLAG_RST = 0x04
    const val FLAG_PSH = 0x08
    const val FLAG_ACK = 0x10

    fun parse(data: ByteArray, offset: Int, length: Int): TcpHeader? {
        if (length - offset < 20) return null
        val srcPort = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
        val dstPort = ((data[offset + 2].toInt() and 0xFF) shl 8) or (data[offset + 3].toInt() and 0xFF)
        val seq = ((data[offset + 4].toLong() and 0xFF) shl 24) or
            ((data[offset + 5].toLong() and 0xFF) shl 16) or
            ((data[offset + 6].toLong() and 0xFF) shl 8) or
            (data[offset + 7].toLong() and 0xFF)
        val ack = ((data[offset + 8].toLong() and 0xFF) shl 24) or
            ((data[offset + 9].toLong() and 0xFF) shl 16) or
            ((data[offset + 10].toLong() and 0xFF) shl 8) or
            (data[offset + 11].toLong() and 0xFF)
        val dataOffset = ((data[offset + 12].toInt() shr 4) and 0xF) * 4
        if (dataOffset < 20 || offset + dataOffset > length) return null
        val flags = data[offset + 13].toInt() and 0xFF
        val window = ((data[offset + 14].toInt() and 0xFF) shl 8) or (data[offset + 15].toInt() and 0xFF)
        return TcpHeader(srcPort, dstPort, seq, ack, dataOffset, flags, window, offset + dataOffset)
    }

    fun build(
        srcAddress: ByteArray,
        dstAddress: ByteArray,
        srcPort: Int,
        dstPort: Int,
        sequenceNumber: Long,
        acknowledgementNumber: Long,
        flags: Int,
        windowSize: Int = 8192,
        payload: ByteArray = ByteArray(0),
        payloadLength: Int = payload.size,
        mss: Int? = null
    ): ByteArray {
        val optionsLength = if (mss != null) 4 else 0
        val headerLength = 20 + optionsLength
        val totalLength = headerLength + payloadLength
        val packet = ByteArray(totalLength)
        packet[0] = (srcPort shr 8).toByte()
        packet[1] = srcPort.toByte()
        packet[2] = (dstPort shr 8).toByte()
        packet[3] = dstPort.toByte()
        packet[4] = (sequenceNumber shr 24).toByte()
        packet[5] = (sequenceNumber shr 16).toByte()
        packet[6] = (sequenceNumber shr 8).toByte()
        packet[7] = sequenceNumber.toByte()
        packet[8] = (acknowledgementNumber shr 24).toByte()
        packet[9] = (acknowledgementNumber shr 16).toByte()
        packet[10] = (acknowledgementNumber shr 8).toByte()
        packet[11] = acknowledgementNumber.toByte()
        packet[12] = ((headerLength / 4) shl 4).toByte()
        packet[13] = flags.toByte()
        packet[14] = (windowSize shr 8).toByte()
        packet[15] = windowSize.toByte()
        packet[16] = 0
        packet[17] = 0
        packet[18] = 0
        packet[19] = 0
        if (mss != null) {
            packet[20] = 2
            packet[21] = 4
            packet[22] = (mss shr 8).toByte()
            packet[23] = mss.toByte()
        }
        System.arraycopy(payload, 0, packet, headerLength, payloadLength)
        val checksum = Checksum.computePseudoHeader(
            srcAddress, dstAddress, IpPacket.PROTOCOL_TCP, packet, 0, totalLength
        )
        packet[16] = (checksum shr 8).toByte()
        packet[17] = checksum.toByte()
        return packet
    }
}
