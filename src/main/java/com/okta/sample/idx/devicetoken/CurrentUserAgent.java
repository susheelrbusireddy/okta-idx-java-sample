package com.okta.sample.idx.devicetoken;

import java.util.regex.Pattern;

public final class CurrentUserAgent {

    private static final int MAX_LENGTH = 512;
    private static final Pattern NOT_PRINTABLE_ASCII = Pattern.compile("[^\\x20-\\x7E]");
    private static final ThreadLocal<String> HOLDER = new ThreadLocal<>();

    private CurrentUserAgent() {
    }

    public static void set(String userAgent) {
        HOLDER.set(sanitize(userAgent));
    }

    public static String get() {
        return HOLDER.get();
    }

    public static void clear() {
        HOLDER.remove();
    }

    static String sanitize(String userAgent) {
        if (userAgent == null) {
            return null;
        }
        String cleaned = NOT_PRINTABLE_ASCII.matcher(userAgent).replaceAll("").trim();
        if (cleaned.length() > MAX_LENGTH) {
            cleaned = cleaned.substring(0, MAX_LENGTH);
        }
        return cleaned.isEmpty() ? null : cleaned;
    }
}
