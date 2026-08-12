package com.wgtunnel.backend

interface Tunnel {
    val id: Int
    val name: String
    val isMetered: Boolean
    val scriptsEnabled: Boolean

    val ipStrategy: IpStrategy
    val features: Set<Feature>

    fun updateState(state: State)

    sealed interface State {
        sealed class Up : State {
            data object Healthy : Up()

            data object HandshakeFailure : Up()
        }

        data object Down : State

        data object Starting : State

        data object Stopping : State

        companion object {
            fun fromNative(code: Int): State? {
                return when (code) {
                    0 -> Up.Healthy
                    1 -> Up.HandshakeFailure
                    99 -> Down
                    else -> null
                }
            }
        }
    }

    sealed interface IpStrategy {
        data object Ipv4Only : IpStrategy

        data class PreferIpv6(val recoveryEnabled: Boolean = true) : IpStrategy
    }

    sealed interface Feature {

        data class ActiveConfigMonitor(val intervalSeconds: Int = 3) : Feature

        /**
         * All recovery behaviour for this tunnel.
         *
         * @param seamlessRecovery full tunnel bounce after sustained HandshakeFailure, maintaining
         *   the current config and skipping deep device idle / Doze to prevent false positives
         *   (screen-off is allowed so background traffic can recover)
         * @param dynamicDnsRecovery performs a fresh resolve bypassing the tunnel and updating the
         *   peers
         * @param ipv6Recovery based on IPStrategy settings. Attempts to recovery to IPv6 endpoints
         *   once per network when tunnel is healthy
         * @param ipv4Fallback only runs with IPStrategy is PreferIpv6, runs once per network when
         *   there are tunnel failures to fall back to IPv4 endpoints
         */
        data class Recovery(
            val seamlessRecovery: Boolean,
            val dynamicDnsRecovery: Boolean,
            internal val ipv4Fallback: Boolean = false,
            internal val ipv6Recovery: Boolean = false,
        ) : Feature
    }
}
