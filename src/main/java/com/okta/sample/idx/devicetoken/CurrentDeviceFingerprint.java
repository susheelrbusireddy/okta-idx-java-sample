package com.okta.sample.idx.devicetoken;

import java.util.regex.Pattern;

public final class CurrentDeviceFingerprint {

    public static final String COOKIE_NAME = "X-Device-Fingerprint";
    public static final int COOKIE_MAX_AGE_DAYS = 730;

    private static final Pattern VALID_VALUE = Pattern.compile("[A-Za-z0-9_-]{1,128}");
    private static final ThreadLocal<String> HOLDER = new ThreadLocal<>();

    private CurrentDeviceFingerprint() {
    }

    public static void set(String fingerprint) {
        HOLDER.set(fingerprint);
    }

    public static String get() {
        return HOLDER.get();
    }

    public static void clear() {
        HOLDER.remove();
    }

    public static boolean isValid(String fingerprint) {
        return fingerprint != null && VALID_VALUE.matcher(fingerprint).matches();
    }
}
