package com.netshieldx.app

import android.app.Application
import com.netshieldx.app.data.db.AppDatabase
import com.netshieldx.app.data.repository.NetShieldRepository
import com.netshieldx.app.notification.NotificationHelper

class NetShieldApplication : Application() {
    lateinit var repository: NetShieldRepository
        private set

    override fun onCreate() {
        super.onCreate()
        NotificationHelper.createChannels(this)
        repository = NetShieldRepository(AppDatabase.getInstance(this))
    }
}
