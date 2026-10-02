package com.okta.sample.idx.devicetoken;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Duration;
import java.util.UUID;

/**
 * Resolves the device token for every incoming request (reusing the browser's persisted
 * {@link #DEVICE_TOKEN_COOKIE_NAME} cookie, or minting and persisting a new one on first visit)
 * and publishes it via {@link CurrentDeviceToken} for the duration of the request. Running this
 * for every request - not just {@code /login} - means every IDX HTTP call made anywhere in a
 * multi-step flow (select-authenticator, verify, ...) is attributed to the same device.
 */
@Component
public final class DeviceTokenFilter implements Filter {

    private static final String DEVICE_TOKEN_COOKIE_NAME = "okta-sample-device-token";
    private static final int DEVICE_TOKEN_COOKIE_MAX_AGE_DAYS = 730;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        try {
            CurrentDeviceToken.set(resolveDeviceToken(httpRequest, httpResponse));
            CurrentDeviceFingerprint.set(resolveDeviceFingerprint(httpRequest));
            chain.doFilter(request, response);
        } finally {
            CurrentDeviceToken.clear();
            CurrentDeviceFingerprint.clear();
        }
    }

    private static String resolveDeviceToken(HttpServletRequest request, HttpServletResponse response) {
        String existing = readDeviceTokenCookie(request);
        return existing != null && !existing.isBlank() ? existing : generateAndPersistDeviceToken(response);
    }

    private static String readDeviceTokenCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (DEVICE_TOKEN_COOKIE_NAME.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    private static String resolveDeviceFingerprint(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (CurrentDeviceFingerprint.COOKIE_NAME.equals(cookie.getName())
                    && CurrentDeviceFingerprint.isValid(cookie.getValue())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    private static String generateAndPersistDeviceToken(HttpServletResponse response) {
        String deviceToken = UUID.randomUUID().toString().replace("-", "");

        ResponseCookie cookie = ResponseCookie.from(DEVICE_TOKEN_COOKIE_NAME, deviceToken)
                .httpOnly(true)
                .path("/")
                .maxAge(Duration.ofDays(DEVICE_TOKEN_COOKIE_MAX_AGE_DAYS))
                .sameSite("Lax")
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        return deviceToken;
    }
}
