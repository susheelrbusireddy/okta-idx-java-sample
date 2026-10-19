package com.okta.sample.idx.devicetoken;

public final class CurrentClientIp {

    private static final ThreadLocal<String> HOLDER = new ThreadLocal<>();

    private CurrentClientIp() {
    }

    public static void set(String clientIp) {
        HOLDER.set(clientIp);
    }

    public static String get() {
        return HOLDER.get();
    }

    public static void clear() {
        HOLDER.remove();
    }
}
