package com.okta.sample.idx.web;

import com.okta.idx.sdk.api.client.IDXAuthenticationWrapper;
import com.okta.sample.idx.devicetoken.CurrentDeviceFingerprint;
import com.okta.sample.idx.devicetoken.CurrentDeviceToken;
import com.okta.sample.idx.service.ClaimsService;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.web.server.ResponseStatusException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

class AuthControllerDeviceFingerprintTest {

    private static final String VISITOR_ID = "0123456789abcdef0123456789abcdef";

    @AfterEach
    void clearRequestState() {
        CurrentDeviceFingerprint.clear();
        CurrentDeviceToken.clear();
    }

    @Test
    void firstLoginPageDoesNotCallOktaBeforeFingerprintIsStored() {
        IDXAuthenticationWrapper idx = mock(IDXAuthenticationWrapper.class);
        AuthController controller = new AuthController(idx, mock(ClaimsService.class));
        ExtendedModelMap model = new ExtendedModelMap();

        assertThat(controller.loginForm(new MockHttpSession(), model)).isEqualTo("login");
        assertThat(model.get("needsDeviceFingerprint")).isEqualTo(true);
        verifyNoInteractions(idx);
    }

    @Test
    void storesValidFingerprintAsHttpOnlySecureCookieForSameOriginRequest() {
        AuthController controller = new AuthController(mock(IDXAuthenticationWrapper.class), mock(ClaimsService.class));
        MockHttpServletRequest request = sameOriginHttpsRequest();

        var response = controller.storeDeviceFingerprint(VISITOR_ID, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(response.getHeaders().getFirst(HttpHeaders.SET_COOKIE))
                .contains("X-Device-Fingerprint=" + VISITOR_ID)
                .contains("Path=/")
                .contains("Max-Age=63072000")
                .contains("Secure")
                .contains("HttpOnly")
                .contains("SameSite=Lax");
    }

    @Test
    void rejectsInvalidVisitorIdsAndCrossOriginRequests() {
        AuthController controller = new AuthController(mock(IDXAuthenticationWrapper.class), mock(ClaimsService.class));
        MockHttpServletRequest request = sameOriginHttpsRequest();

        assertThrows(ResponseStatusException.class, () -> controller.storeDeviceFingerprint("bad value", request));

        MockHttpServletRequest crossOriginRequest = httpsRequest("https://attacker.example");
        assertThrows(ResponseStatusException.class,
                () -> controller.storeDeviceFingerprint(VISITOR_ID, crossOriginRequest));
    }

    private static MockHttpServletRequest sameOriginHttpsRequest() {
        return httpsRequest("https://localhost");
    }

    private static MockHttpServletRequest httpsRequest(String origin) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/device-fingerprint");
        request.setScheme("https");
        request.setServerName("localhost");
        request.setServerPort(443);
        request.setSecure(true);
        request.addHeader("Origin", origin);
        return request;
    }
}
