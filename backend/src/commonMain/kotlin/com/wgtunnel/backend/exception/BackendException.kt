package com.wgtunnel.backend.exception

sealed class BackendException : Exception() {

    class InternalError(override val message: String) : BackendException()

    class Unauthorized(override val message: String) : BackendException()

    class Socks5PortUnavailable(override val message: String, val port: Int) : BackendException()

    class HttpPortUnavailable(override val message: String, val port: Int) : BackendException()

    class ListenPortUnavailable(override val message: String, val port: Int) : BackendException()

    class ConfigMissingDNS(override val message: String) : BackendException()
}
