-keepclasseswithmembernames class com.wgtunnel.backend.** {
    native <methods>;
}

-keepclassmembers class com.wgtunnel.backend.dns.NativeDnsResolver {
    native <methods>;
}

-keepclassmembers class com.wgtunnel.backend.dns.UnderlayDnsBridge {
    public static <methods>;
}
-keepclassmembers class com.wgtunnel.backend.network.NetworkMonitorNative {
    public static <methods>;
}
# Interfaces invoked from native
-keep interface com.wgtunnel.backend.TunnelStatusCallback {
    void onStatus(int, int);
}
-keep class * implements com.wgtunnel.backend.TunnelStatusCallback {
    void onStatus(int, int);
}
-keep interface com.wgtunnel.backend.SocketProtector {
    int bypass(int);
}
-keep class * implements com.wgtunnel.backend.SocketProtector {
    int bypass(int);
}