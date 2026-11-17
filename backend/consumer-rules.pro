-keepclasseswithmembernames class com.wgtunnel.backend.** {
    native <methods>;
}

-keepclassmembers class com.wgtunnel.backend.dns.NativeDnsResolver {
    native <methods>;
}

-keepclassmembers class com.wgtunnel.backend.dns.UnderlayDnsBridge {
    public static <methods>;
}
# Called from vpn_jni_android.c by name
-keepclassmembers class com.wgtunnel.backend.StrictSplitBridge {
    public static boolean allow(java.lang.String, java.lang.String, int, java.lang.String, int);
}
-keepclassmembers class com.wgtunnel.backend.network.NetworkMonitorNative {
    public static <methods>;
}
-keepclassmembers class com.wgtunnel.backend.StrictSplitBridge {
    public static boolean allow(java.lang.String, java.lang.String, int, java.lang.String, int);
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