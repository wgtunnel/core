package com.wgtunnel.backend

import com.wgtunnel.backend.service.RuntimeManager

object BackendRuntime {
    @Volatile
    var runtimeManager: RuntimeManager? = null
        private set

    @Volatile
    var backend: Backend? = null
        private set

    @Volatile
    var applicationProvider: ApplicationProvider? = null
        private set

    fun install(
        runtimeManager: RuntimeManager,
        backend: Backend,
        applicationProvider: ApplicationProvider,
    ) {
        this.runtimeManager = runtimeManager
        this.backend = backend
        this.applicationProvider = applicationProvider
    }

    fun requireManager(): RuntimeManager =
        runtimeManager ?: error("BackendRuntime.install() not called")

    fun requireBackend(): Backend = backend ?: error("BackendRuntime.install() not called")

    fun requireProvider(): ApplicationProvider =
        applicationProvider ?: error("BackendRuntime.install() not called")
}
