package com.netshieldx.app.vpn

import com.netshieldx.app.domain.ThreatAssessment
import com.netshieldx.app.domain.ThreatClassifier
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.random.Random

/**
 * Callback dari mesin VPN ke service untuk pencatatan dan notifikasi.
 * Semua pemrosesan paket terjadi lokal di perangkat.
 */
interface VpnCallbacks {
    fun protectSocket(socket: Socket): Boolean
    fun protectSocket(socket: DatagramSocket): Boolean
    fun getDnsFilter(): DnsFilter
    fun getUpstreamDns(): String
    fun getCustomBlocked(): Map<FilterCategory, Set<String>>
    fun getAllowlist(): Set<String>
    fun isUidBlocked(uid: Int): Boolean
    fun getModeForUid(uid: Int): String
    fun onDnsEvent(domain: String, uid: Int, decision: FilterDecision)
    fun onThreat(assessment: ThreatAssessment)
    fun onConnectionOpened(protocol: String, dstAddress: String, dstPort: Int, uid: Int)
    fun onConnectionClosed(protocol: String, uid: Int, bytesRx: Long, bytesTx: Long)
    fun onAlertModeConnection(uid: Int, dstAddress: String, dstPort: Int)
}

/**
 * Mesin pemrosesan paket VPN lokal.
 *
 * Protokol yang didukung (didokumentasikan juga di README):
 * - IPv4 (paket IPv6 tidak diproses).
 * - DNS UDP port 53: diintersep lokal, difilter, lalu diteruskan ke
 *   upstream DNS bila diizinkan.
 * - TCP IPv4: forwarding lewat Socket dengan userspace TCP state machine
 *   (SYN, SYN-ACK, ACK, PSH, FIN, RST).
 * - UDP IPv4 non-DNS: forwarding lewat DatagramSocket per sesi.
 * - ICMP: tidak diteruskan (dijatuhkan).
 *
 * HTTPS tidak pernah dibaca isinya. Tidak ada MITM, tidak ada instalasi CA.
 */
class VpnEngine(
    private val tunInput: FileInputStream,
    private val tunOutput: FileOutputStream,
    private val virtualDnsAddress: ByteArray,
    private val callbacks: VpnCallbacks
) {
    private val running = AtomicBoolean(false)
    private val executor: ExecutorService = Executors.newCachedThreadPool()
    private val dnsCache = DnsCache()
    private val uidMapper = UidMapper()

    private val tcpConnections = ConcurrentHashMap<String, TcpConnection>()
    private val udpSessions = ConcurrentHashMap<String, UdpSession>()

    val bytesReceived = AtomicLong(0)
    val bytesSent = AtomicLong(0)
    val connectionsProcessed = AtomicLong(0)
    val packetsProcessed = AtomicLong(0)

    fun start() {
        if (!running.compareAndSet(false, true)) return
        executor.execute { readLoop() }
        executor.execute { cleanupLoop() }
    }

    fun stop() {
        running.set(false)
        try {
            tcpConnections.values.forEach { it.close() }
            tcpConnections.clear()
        } catch (_: Exception) {
        }
        try {
            udpSessions.values.forEach { it.close() }
            udpSessions.clear()
        } catch (_: Exception) {
        }
        executor.shutdownNow()
    }

    fun isRunning(): Boolean = running.get()

    private fun readLoop() {
        val buffer = ByteArray(32767)
        while (running.get()) {
            try {
                val length = tunInput.read(buffer)
                if (length <= 0) continue
                packetsProcessed.incrementAndGet()
                val packet = buffer.copyOf(length)
                executor.execute { processPacket(packet) }
            } catch (e: IOException) {
                if (running.get()) {
                    try {
                        Thread.sleep(50)
                    } catch (_: InterruptedException) {
                        break
                    }
                } else {
                    break
                }
            } catch (_: InterruptedException) {
                break
            }
        }
    }

    private fun cleanupLoop() {
        while (running.get()) {
            try {
                Thread.sleep(30_000)
                val now = System.currentTimeMillis()
                udpSessions.entries.removeIf { (_, session) ->
                    if (now - session.lastActivityMs > 60_000) {
                        session.close()
                        true
                    } else false
                }
                tcpConnections.entries.removeIf { (_, conn) ->
                    if (conn.isClosed()) true else false
                }
            } catch (_: InterruptedException) {
                break
            }
        }
    }

    @Synchronized
    private fun writeToTun(packet: ByteArray) {
        try {
            tunOutput.write(packet)
            tunOutput.flush()
        } catch (_: IOException) {
        }
    }

    private fun processPacket(packet: ByteArray) {
        val ip = IpPacket.parse(packet, packet.size) ?: return
        when (ip.protocol) {
            IpPacket.PROTOCOL_UDP -> processUdp(ip, packet)
            IpPacket.PROTOCOL_TCP -> processTcp(ip, packet)
            else -> {
                // ICMP dan protokol lain tidak diteruskan.
            }
        }
    }

    // ---------------- UDP ----------------

    private fun processUdp(ip: IpHeader, packet: ByteArray) {
        val udp = UdpPacket.parse(packet, ip.payloadOffset, ip.totalLength) ?: return
        val payloadLength = udp.length - UdpPacket.HEADER_LENGTH
        if (payloadLength < 0) return
        val payload = packet.copyOfRange(udp.payloadOffset, udp.payloadOffset + payloadLength)
        val uid = uidMapper.getUidForPort(IpPacket.PROTOCOL_UDP, udp.srcPort)

        if (callbacks.isUidBlocked(uid)) {
            return
        }
        if (callbacks.getModeForUid(uid) == "ALERT") {
            callbacks.onAlertModeConnection(uid, ip.dstAddressString(), udp.dstPort)
        }

        if (udp.dstPort == 53) {
            processDns(ip, udp, payload, uid)
            return
        }
        forwardUdp(ip, udp, payload)
    }

    private fun processDns(ip: IpHeader, udp: UdpHeader, payload: ByteArray, uid: Int) {
        val query = DnsPacket.parseQuery(payload, payload.size)
        val domain = query?.firstQuestion?.name?.let { DnsPacket.normalizeDomain(it) }
        val filter = callbacks.getDnsFilter()
        val decision = if (domain != null) filter.decide(domain) else FilterDecision.Allowed

        if (domain != null) {
            callbacks.onDnsEvent(domain, uid, decision)
            val assessment = ThreatClassifier.classify(
                domain,
                BlocklistManager.DEFAULT_PHISHING,
                BlocklistManager.DEFAULT_MALWARE,
                BlocklistManager.DEFAULT_C2
            )
            if (assessment != null) callbacks.onThreat(assessment)
        }

        if (decision is FilterDecision.Blocked) {
            val responsePayload = if (query != null) {
                DnsPacket.buildNxDomainResponse(query, payload, payload.size)
            } else return
            sendUdpResponse(ip, udp, responsePayload)
            return
        }

        if (query != null && domain != null) {
            val cacheKey = DnsCache.key(domain, query.firstQuestion?.type ?: DnsPacket.TYPE_A)
            val cached = dnsCache.get(cacheKey)
            if (cached != null) {
                val rewritten = rewriteTransactionId(cached, query.transactionId)
                sendUdpResponse(ip, udp, rewritten)
                return
            }
        }

        executor.execute {
            try {
                val upstream = InetAddress.getByName(callbacks.getUpstreamDns())
                val socket = DatagramSocket()
                if (!callbacks.protectSocket(socket)) {
                    socket.close()
                    return@execute
                }
                socket.soTimeout = 5000
                socket.send(DatagramPacket(payload, payload.size, upstream, 53))
                val responseBuffer = ByteArray(4096)
                val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
                socket.receive(responsePacket)
                socket.close()
                val response = responseBuffer.copyOf(responsePacket.length)
                if (query != null && domain != null) {
                    val ttl = extractTtl(response) ?: 300
                    val cacheKey = DnsCache.key(domain, query.firstQuestion?.type ?: DnsPacket.TYPE_A)
                    dnsCache.put(cacheKey, response, ttl)
                }
                bytesReceived.addAndGet(response.size.toLong())
                sendUdpResponse(ip, udp, response)
            } catch (_: Exception) {
            }
        }
    }

    private fun sendUdpResponse(ip: IpHeader, udp: UdpHeader, payload: ByteArray) {
        val udpPacket = UdpPacket.build(
            ip.dstAddress, ip.srcAddress, udp.dstPort, udp.srcPort, payload
        )
        val ipPacket = IpPacket.build(
            ip.dstAddress, ip.srcAddress, IpPacket.PROTOCOL_UDP, udpPacket
        )
        bytesSent.addAndGet(ipPacket.size.toLong())
        writeToTun(ipPacket)
    }

    private fun forwardUdp(ip: IpHeader, udp: UdpHeader, payload: ByteArray) {
        val key = "${ip.srcAddressString()}:${udp.srcPort}->${ip.dstAddressString()}:${udp.dstPort}"
        var session = udpSessions[key]
        if (session == null || session.isClosed()) {
            try {
                val socket = DatagramSocket()
                if (!callbacks.protectSocket(socket)) {
                    socket.close()
                    return
                }
                session = UdpSession(socket, ip, udp)
                udpSessions[key] = session
                connectionsProcessed.incrementAndGet()
                val uid = uidMapper.getUidForPort(IpPacket.PROTOCOL_UDP, udp.srcPort)
                callbacks.onConnectionOpened("UDP", ip.dstAddressString(), udp.dstPort, uid)
                executor.execute { session.readLoop() }
            } catch (_: Exception) {
                return
            }
        }
        session.lastActivityMs = System.currentTimeMillis()
        try {
            val dst = InetAddress.getByAddress(ip.dstAddress)
            session.socket.send(DatagramPacket(payload, payload.size, dst, udp.dstPort))
            bytesSent.addAndGet(payload.size.toLong())
        } catch (_: Exception) {
            session.close()
            udpSessions.remove(key)
        }
    }

    private inner class UdpSession(
        val socket: DatagramSocket,
        private val clientIp: IpHeader,
        private val clientUdp: UdpHeader
    ) {
        @Volatile var lastActivityMs: Long = System.currentTimeMillis()
        private val closed = AtomicBoolean(false)

        fun isClosed(): Boolean = closed.get() || socket.isClosed

        fun readLoop() {
            val buffer = ByteArray(4096)
            try {
                socket.soTimeout = 60_000
                while (running.get() && !closed.get()) {
                    val packet = DatagramPacket(buffer, buffer.size)
                    try {
                        socket.receive(packet)
                    } catch (_: java.net.SocketTimeoutException) {
                        break
                    }
                    lastActivityMs = System.currentTimeMillis()
                    val payload = buffer.copyOf(packet.length)
                    bytesReceived.addAndGet(payload.size.toLong())
                    sendUdpResponse(clientIp, clientUdp, payload)
                }
            } catch (_: Exception) {
            } finally {
                close()
            }
        }

        fun close() {
            if (closed.compareAndSet(false, true)) {
                try {
                    socket.close()
                } catch (_: Exception) {
                }
            }
        }
    }

    // ---------------- TCP ----------------

    private fun processTcp(ip: IpHeader, packet: ByteArray) {
        val tcp = TcpPacket.parse(packet, ip.payloadOffset, ip.totalLength) ?: return
        val payloadLength = ip.totalLength - tcp.payloadOffset
        val payload = if (payloadLength > 0) {
            packet.copyOfRange(tcp.payloadOffset, tcp.payloadOffset + payloadLength)
        } else ByteArray(0)
        val key = "${ip.srcAddressString()}:${tcp.srcPort}->${ip.dstAddressString()}:${tcp.dstPort}"
        val uid = uidMapper.getUidForPort(IpPacket.PROTOCOL_TCP, tcp.srcPort)

        if (callbacks.isUidBlocked(uid)) {
            if (tcp.isSyn && !tcp.isAck) {
                sendTcpRst(ip, tcp)
            }
            return
        }
        if (callbacks.getModeForUid(uid) == "ALERT" && tcp.isSyn && !tcp.isAck) {
            callbacks.onAlertModeConnection(uid, ip.dstAddressString(), tcp.dstPort)
        }

        var connection = tcpConnections[key]
        if (connection == null) {
            if (!tcp.isSyn || tcp.isAck) {
                sendTcpRst(ip, tcp)
                return
            }
            connection = TcpConnection(ip, tcp, key, uid)
            tcpConnections[key] = connection
            connectionsProcessed.incrementAndGet()
            callbacks.onConnectionOpened("TCP", ip.dstAddressString(), tcp.dstPort, uid)
            connection.start()
            return
        }
        connection.handleClientPacket(tcp, payload)
    }

    private fun sendTcpRst(ip: IpHeader, tcp: TcpHeader) {
        val ackNumber = if (tcp.isAck) tcp.acknowledgementNumber else tcp.sequenceNumber + 1
        val tcpPacket = TcpPacket.build(
            ip.dstAddress, ip.srcAddress, tcp.dstPort, tcp.srcPort,
            0L, ackNumber, TcpPacket.FLAG_RST or TcpPacket.FLAG_ACK
        )
        val ipPacket = IpPacket.build(
            ip.dstAddress, ip.srcAddress, IpPacket.PROTOCOL_TCP, tcpPacket
        )
        writeToTun(ipPacket)
    }

    private inner class TcpConnection(
        private val clientIp: IpHeader,
        syn: TcpHeader,
        private val key: String,
        private val uid: Int
    ) {
        private val dstAddress: ByteArray = clientIp.dstAddress.copyOf()
        private val dstPort: Int = syn.dstPort
        private val srcPort: Int = syn.srcPort
        private val clientAddress: ByteArray = clientIp.srcAddress.copyOf()

        private var clientSeqNext: Long = syn.sequenceNumber + 1
        private var serverSeqNext: Long = Random.nextLong(0, 1_000_000_000L)
        private val serverInitialSeq: Long = serverSeqNext
        private var connected = false
        private var clientFinReceived = false
        private var serverFinSent = false
        private val closed = AtomicBoolean(false)

        private var socket: Socket? = null
        private var bytesRx: Long = 0
        private var bytesTx: Long = 0

        fun isClosed(): Boolean = closed.get()

        fun start() {
            executor.execute {
                try {
                    val sock = Socket()
                    if (!callbacks.protectSocket(sock)) {
                        sock.close()
                        sendRstToClient()
                        close()
                        return@execute
                    }
                    sock.soTimeout = 30_000
                    sock.connect(InetSocketAddress(InetAddress.getByAddress(dstAddress), dstPort), 10_000)
                    sock.soTimeout = 0
                    socket = sock
                    connected = true
                    sendSynAck()
                    executor.execute { readFromServer() }
                } catch (_: Exception) {
                    sendRstToClient()
                    close()
                }
            }
        }

        private fun sendSynAck() {
            val tcpPacket = TcpPacket.build(
                dstAddress, clientAddress, dstPort, srcPort,
                serverSeqNext, clientSeqNext,
                TcpPacket.FLAG_SYN or TcpPacket.FLAG_ACK, mss = 1460
            )
            serverSeqNext += 1
            val ipPacket = IpPacket.build(
                dstAddress, clientAddress, IpPacket.PROTOCOL_TCP, tcpPacket
            )
            bytesSent.addAndGet(ipPacket.size.toLong())
            writeToTun(ipPacket)
        }

        private fun sendRstToClient() {
            val tcpPacket = TcpPacket.build(
                dstAddress, clientAddress, dstPort, srcPort,
                serverSeqNext, clientSeqNext, TcpPacket.FLAG_RST or TcpPacket.FLAG_ACK
            )
            val ipPacket = IpPacket.build(
                dstAddress, clientAddress, IpPacket.PROTOCOL_TCP, tcpPacket
            )
            writeToTun(ipPacket)
        }

        @Synchronized
        fun handleClientPacket(tcp: TcpHeader, payload: ByteArray) {
            if (closed.get()) return
            if (tcp.isRst) {
                close()
                return
            }
            if (payload.isNotEmpty()) {
                if (tcp.sequenceNumber != clientSeqNext) {
                    sendAck()
                    return
                }
                val sock = socket
                if (sock == null || !connected) return
                try {
                    sock.getOutputStream().write(payload)
                    sock.getOutputStream().flush()
                    clientSeqNext += payload.size
                    bytesTx += payload.size
                    bytesSent.addAndGet(payload.size.toLong())
                } catch (_: Exception) {
                    close()
                    return
                }
            }
            if (tcp.isFin) {
                clientSeqNext += 1
                clientFinReceived = true
                sendAck()
                sendFinToClient()
                return
            }
            if (payload.isNotEmpty() || tcp.isAck) {
                sendAck()
            }
        }

        @Synchronized
        private fun sendAck() {
            val tcpPacket = TcpPacket.build(
                dstAddress, clientAddress, dstPort, srcPort,
                serverSeqNext, clientSeqNext, TcpPacket.FLAG_ACK
            )
            val ipPacket = IpPacket.build(
                dstAddress, clientAddress, IpPacket.PROTOCOL_TCP, tcpPacket
            )
            bytesSent.addAndGet(ipPacket.size.toLong())
            writeToTun(ipPacket)
        }

        @Synchronized
        private fun sendFinToClient() {
            if (serverFinSent) return
            serverFinSent = true
            val tcpPacket = TcpPacket.build(
                dstAddress, clientAddress, dstPort, srcPort,
                serverSeqNext, clientSeqNext, TcpPacket.FLAG_FIN or TcpPacket.FLAG_ACK
            )
            serverSeqNext += 1
            val ipPacket = IpPacket.build(
                dstAddress, clientAddress, IpPacket.PROTOCOL_TCP, tcpPacket
            )
            writeToTun(ipPacket)
            executor.execute {
                try {
                    Thread.sleep(2_000)
                } catch (_: InterruptedException) {
                }
                close()
            }
        }

        private fun readFromServer() {
            val sock = socket ?: return
            val buffer = ByteArray(8192)
            try {
                val input = sock.getInputStream()
                while (running.get() && !closed.get()) {
                    val read = input.read(buffer)
                    if (read <= 0) break
                    val payload = buffer.copyOf(read)
                    synchronized(this) {
                        if (closed.get()) return@synchronized
                        val tcpPacket = TcpPacket.build(
                            dstAddress, clientAddress, dstPort, srcPort,
                            serverSeqNext, clientSeqNext,
                            TcpPacket.FLAG_PSH or TcpPacket.FLAG_ACK,
                            payload = payload
                        )
                        serverSeqNext += read
                        val ipPacket = IpPacket.build(
                            dstAddress, clientAddress, IpPacket.PROTOCOL_TCP, tcpPacket
                        )
                        bytesRx += read
                        bytesReceived.addAndGet(ipPacket.size.toLong())
                        writeToTun(ipPacket)
                    }
                }
            } catch (_: Exception) {
            } finally {
                if (!clientFinReceived) {
                    sendFinToClient()
                }
            }
        }

        fun close() {
            if (closed.compareAndSet(false, true)) {
                try {
                    socket?.close()
                } catch (_: Exception) {
                }
                tcpConnections.remove(key)
                callbacks.onConnectionClosed("TCP", uid, bytesRx, bytesTx)
            }
        }
    }

    companion object {
        fun rewriteTransactionId(response: ByteArray, transactionId: Int): ByteArray {
            val out = response.copyOf()
            if (out.size >= 2) {
                out[0] = (transactionId shr 8).toByte()
                out[1] = transactionId.toByte()
            }
            return out
        }

        /** Ekstrak TTL dari jawaban pertama respons DNS, atau null. */
        fun extractTtl(response: ByteArray): Int? {
            try {
                if (response.size < 12) return null
                val qdCount = ((response[4].toInt() and 0xFF) shl 8) or (response[5].toInt() and 0xFF)
                val anCount = ((response[6].toInt() and 0xFF) shl 8) or (response[7].toInt() and 0xFF)
                if (anCount == 0) return null
                var offset = 12
                repeat(qdCount) {
                    val name = DnsPacket.readName(response, offset, response.size) ?: return null
                    offset = name.second + 4
                }
                val answerName = DnsPacket.readName(response, offset, response.size) ?: return null
                offset = answerName.second
                if (offset + 10 > response.size) return null
                val ttl = ((response[offset + 4].toLong() and 0xFF) shl 24) or
                    ((response[offset + 5].toLong() and 0xFF) shl 16) or
                    ((response[offset + 6].toLong() and 0xFF) shl 8) or
                    (response[offset + 7].toLong() and 0xFF)
                return ttl.toInt().coerceIn(10, 3600)
            } catch (_: Exception) {
                return null
            }
        }
    }
}
