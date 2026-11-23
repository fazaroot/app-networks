package com.netshieldx.app

import com.netshieldx.app.domain.RiskLevel
import com.netshieldx.app.domain.ThreatClassifier
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ThreatClassifierTest {

    private val phishing = setOf("phish.example.com")
    private val malware = setOf("malware.example.com")
    private val c2 = setOf("c2.example.com")

    @Test
    fun c2Domain_isCriticalAndListed() {
        val result = ThreatClassifier.classify("c2.example.com", phishing, malware, c2)
        assertNotNull(result)
        assertEquals(RiskLevel.CRITICAL, result!!.level)
        assertTrue(result.listed)
    }

    @Test
    fun malwareSubdomain_isHigh() {
        val result = ThreatClassifier.classify("dl.malware.example.com", phishing, malware, c2)
        assertNotNull(result)
        assertEquals(RiskLevel.HIGH, result!!.level)
    }

    @Test
    fun phishingDomain_isHigh() {
        val result = ThreatClassifier.classify("phish.example.com", phishing, malware, c2)
        assertNotNull(result)
        assertEquals(RiskLevel.HIGH, result!!.level)
    }

    @Test
    fun cleanDomain_returnsNull() {
        assertNull(ThreatClassifier.classify("example.com", phishing, malware, c2))
        assertNull(ThreatClassifier.classify("google.com", phishing, malware, c2))
    }

    @Test
    fun suspiciousHeuristic_isLowAndUnlisted() {
        val longDomain = "a".repeat(65) + ".com"
        val result = ThreatClassifier.classify(longDomain, phishing, malware, c2)
        assertNotNull(result)
        assertEquals(RiskLevel.LOW, result!!.level)
        assertFalse(result.listed)
    }

    @Test
    fun emptyDomain_returnsNull() {
        assertNull(ThreatClassifier.classify("", phishing, malware, c2))
        assertNull(ThreatClassifier.classify("   ", phishing, malware, c2))
    }
}
