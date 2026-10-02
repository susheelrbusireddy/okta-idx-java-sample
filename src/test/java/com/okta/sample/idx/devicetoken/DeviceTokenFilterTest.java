package com.okta.sample.idx.devicetoken;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DeviceTokenFilterTest {

    private static final String VISITOR_ID = "0123456789abcdef0123456789abcdef";

    @AfterEach
    void clearRequestState() {
        CurrentDeviceFingerprint.clear();
        CurrentDeviceToken.clear();
    }

    @Test
    void exposesValidBrowserCookiesOnlyDuringRequest() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login");
        request.setCookies(
                new Cookie("okta-sample-device-token", "device-token"),
                new Cookie(CurrentDeviceFingerprint.COOKIE_NAME, VISITOR_ID));

        new DeviceTokenFilter().doFilter(request, new MockHttpServletResponse(), (servletRequest, servletResponse) -> {
            assertThat(CurrentDeviceToken.get()).isEqualTo("device-token");
            assertThat(CurrentDeviceFingerprint.get()).isEqualTo(VISITOR_ID);
        });

        assertThat(CurrentDeviceToken.get()).isNull();
        assertThat(CurrentDeviceFingerprint.get()).isNull();
    }

    @Test
    void clearsRequestStateWhenTheChainFails() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login");
        request.setCookies(
                new Cookie("okta-sample-device-token", "device-token"),
                new Cookie(CurrentDeviceFingerprint.COOKIE_NAME, VISITOR_ID));

        assertThrows(ServletException.class, () -> new DeviceTokenFilter().doFilter(
                request,
                new MockHttpServletResponse(),
                (servletRequest, servletResponse) -> { throw new ServletException("failure"); }));

        assertThat(CurrentDeviceToken.get()).isNull();
        assertThat(CurrentDeviceFingerprint.get()).isNull();
    }

    @Test
    void ignoresMalformedFingerprintCookie() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login");
        request.setCookies(new Cookie(CurrentDeviceFingerprint.COOKIE_NAME, "bad value"));

        new DeviceTokenFilter().doFilter(request, new MockHttpServletResponse(), (servletRequest, servletResponse) ->
                assertThat(CurrentDeviceFingerprint.get()).isNull());
    }
}
