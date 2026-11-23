package com.netshieldx.app

import com.netshieldx.app.vpn.DnsCache
import com.netshieldx.app.vpn.DnsFilter
import com.netshieldx.app.vpn.FilterCategory
import com.netshieldx.app.vpn.FilterDecision
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsFilterTest {

    private fun filter(): DnsFilter {
        return DnsFilter().apply {
            setBlocked(FilterCategory.ADS, setOf("ads.example.com", "doubleclick.net"))
            setBlocked(FilterCategory.TRACKER, setOf("tracker.example.com"))
            setBlocked(FilterCategory.PHISHING_MALWARE, setOf("phish.example.com"))
        }
    }

    @Test
    fun exactMatch_blocked() {
        val decision = filter().decide("ads.example.com")
        assertTrue(decision is FilterDecision.Blocked)
        assertEquals(FilterCategory.ADS, (decision as FilterDecision.Blocked).category)
    }

    @Test
    fun subdomainMatch_blocked() {
        val decision = filter().decide("a.b.ads.example.com")
        assertTrue(decision is FilterDecision.Blocked)
        assertEquals("ads.example.com", (decision as FilterDecision.Blocked).matchedRule)
    }

    @Test
    fun unrelatedDomain_allowed() {
        assertTrue(filter().decide("example.com") is FilterDecision.Allowed)
        assertTrue(filter().decide("notads.example.com") is FilterDecision.Allowed)
    }

    @Test
    fun allowlistBeatsBlocklist() {
        val f = filter()
        f.addAllowlist("ads.example.com")
        assertTrue(f.decide("ads.example.com") is FilterDecision.Allowed)
        assertTrue(f.decide("sub.ads.example.com") is FilterDecision.Allowed)
    }

    @Test
    fun disabledCategory_allows() {
        val f = filter()
        f.setCategoryEnabled(FilterCategory.ADS, false)
        assertTrue(f.decide("ads.example.com") is FilterDecision.Allowed)
        assertTrue(f.decide("tracker.example.com") is FilterDecision.Blocked)
    }

    @Test
    fun caseAndTrailingDot_normalized() {
        assertTrue(filter().decide("ADS.EXAMPLE.COM.") is FilterDecision.Blocked)
    }

    @Test
    fun addAndRemoveCustomRule() {
        val f = filter()
        f.addBlocked(FilterCategory.CUSTOM, "custom.example.com")
        assertTrue(f.decide("custom.example.com") is FilterDecision.Blocked)
        f.removeBlocked(FilterCategory.CUSTOM, "custom.example.com")
        assertTrue(f.decide("custom.example.com") is FilterDecision.Allowed)
    }

    @Test
    fun cache_putGetAndExpiry() {
        val cache = DnsCache(maxEntries = 2)
        val response = byteArrayOf(1, 2, 3, 4)
        cache.put("example.com|1", response, ttlSeconds = 60, nowMs = 1000L)
        assertEquals(response.toList(), cache.get("example.com|1", nowMs = 2000L)?.toList())
        assertNull(cache.get("example.com|1", nowMs = 1000L + 61_000L))
    }

    @Test
    fun cache_evictsEldestWhenFull() {
        val cache = DnsCache(maxEntries = 2)
        cache.put("a.com|1", byteArrayOf(1), 60, 1000L)
        cache.put("b.com|1", byteArrayOf(2), 60, 1000L)
        cache.put("c.com|1", byteArrayOf(3), 60, 1000L)
        assertNull(cache.get("a.com|1", 2000L))
        assertEquals(2, cache.size())
    }

    @Test
    fun cache_keyFormat() {
        assertEquals("example.com|28", DnsCache.key("Example.COM.", 28))
    }
}
