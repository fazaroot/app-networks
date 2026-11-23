package com.netshieldx.app.ui.navigation

/** Rute navigasi utama NetShield X. */
sealed class AppRoute(val route: String, val label: String) {
    object Dashboard : AppRoute("dashboard", "Dashboard")
    object Network : AppRoute("network", "Jaringan")
    object Firewall : AppRoute("firewall", "Firewall")
    object Protection : AppRoute("protection", "Proteksi")
    object Settings : AppRoute("settings", "Pengaturan")
    object Privacy : AppRoute("privacy", "Privasi dan Keamanan")

    companion object {
        val bottomBar = listOf(Dashboard, Network, Firewall, Protection, Settings)
    }
}
