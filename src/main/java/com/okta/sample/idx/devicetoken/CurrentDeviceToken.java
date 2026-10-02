package com.okta.sample.idx.devicetoken;

/**
 * Holds the device token for the browser making the current HTTP request. The app's
 * {@code OkHttpClient} is a single shared instance for the whole app, so the token to attach to
 * an outgoing IDX call can't be baked in at client-construction time - it has to be resolved per
 * request. {@link DeviceTokenFilter} sets this once per request and clears it when the request
 * completes.
 */
public final class CurrentDeviceToken {

    private static final ThreadLocal<String> HOLDER = new ThreadLocal<>();

    private CurrentDeviceToken() {
    }

    public static void set(String deviceToken) {
        HOLDER.set(deviceToken);
    }

    public static String get() {
        return HOLDER.get();
    }

    public static void clear() {
        HOLDER.remove();
    }
}
