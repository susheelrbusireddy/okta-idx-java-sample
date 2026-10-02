package com.okta.sample.idx.config;

import com.okta.sample.idx.devicetoken.CurrentDeviceFingerprint;
import com.okta.sample.idx.devicetoken.CurrentDeviceToken;
import okhttp3.Request;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class OktaIdxConfigCookieTest {

    private static final String VISITOR_ID = "0123456789abcdef0123456789abcdef";

    @AfterEach
    void clearRequestState() {
        CurrentDeviceFingerprint.clear();
        CurrentDeviceToken.clear();
    }

    @Test
    void forwardsFingerprintHeaderAndBothCookies() {
        CurrentDeviceToken.set("device-token");
        CurrentDeviceFingerprint.set(VISITOR_ID);
        Request request = new Request.Builder()
                .url("https://example.okta.com/idp/idx/interact")
                .header("Cookie", "session=existing")
                .build();

        Request forwarded = OktaIdxConfig.addDeviceFingerprintHeadersAndCookies(request, request.newBuilder()).build();

        assertThat(forwarded.headers().values("Cookie"))
                .containsExactly("session=existing; DT=device-token; X-Device-Fingerprint=" + VISITOR_ID);
        assertThat(forwarded.headers().values("X-Device-Fingerprint")).containsExactly(VISITOR_ID);
    }

    @Test
    void omitsFingerprintCookieWhenRequestStateIsMissing() {
        Request request = new Request.Builder().url("https://example.okta.com/idp/idx/interact").build();

        Request forwarded = OktaIdxConfig.addDeviceFingerprintHeadersAndCookies(request, request.newBuilder()).build();

        assertThat(forwarded.headers().values("Cookie")).isEmpty();
        assertThat(forwarded.headers().values("X-Device-Fingerprint")).isEmpty();
    }
}
