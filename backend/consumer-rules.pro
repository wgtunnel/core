-keep class com.wgtunnel.tunnel.backend.VpnBackend { *; }
-keep class com.wgtunnel.tunnel.backend.ProxyBackend { *; }

-keepclasseswithmembernames class * {
    native <methods>;
}

# Callbacks called from native to Kotlin
-keep class com.wgtunnel.tunnel.backend.NativeTunnelCallback { *; }
-keepclassmembers class * implements com.wgtunnel.tunnel.backend.NativeTunnelCallback {
    <methods>;
}

-keepclassmembers,includedescriptorclasses class com.wgtunnel.tunnel.backend.TunnelStatusBridge {
    public static void onStatusChanged(int, int);
}

-keep class com.wgtunnel.tunnel.backend.BypassSocket { *; }
-keepclassmembers class com.wgtunnel.tunnel.backend.BypassSocket {
    native <methods>;
}