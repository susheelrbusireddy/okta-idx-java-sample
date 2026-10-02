package com.okta.sample.idx.config;

import com.okta.commons.http.RequestExecutor;
import com.okta.commons.http.okhttp.OkHttpRequestExecutorFactory;
import com.okta.idx.sdk.api.client.IDXAuthenticationWrapper;
import com.okta.idx.sdk.api.client.IDXClient;
import com.okta.idx.sdk.api.config.ClientConfiguration;
import com.okta.sample.idx.devicetoken.CurrentDeviceFingerprint;
import com.okta.sample.idx.devicetoken.CurrentDeviceToken;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okio.Buffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Configuration
@EnableConfigurationProperties(OktaIdxProperties.class)
public class OktaIdxConfig {

    private static final Logger log = LoggerFactory.getLogger(OktaIdxConfig.class);

    /** Name of the cookie Okta itself uses to remember a device across sign-ins. */
    private static final String DT_COOKIE_NAME = "DT";

    /**
     * okta-idx-java's {@code IdentifyRequestBuilder} defaults {@code rememberMe} to false and
     * {@code IDXAuthenticationWrapper.authenticate()} never overrides it, with no public API to do
     * so - so the outgoing identify request body is rewritten in place instead.
     */
    private static final Pattern REMEMBER_ME_FALSE = Pattern.compile("\"rememberMe\"\\s*:\\s*false");

    @Bean
    public IDXAuthenticationWrapper idxAuthenticationWrapper(OktaIdxProperties properties) {
        Set<String> scopes = Arrays.stream(properties.getScopes().split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toCollection(LinkedHashSet::new));

        IDXAuthenticationWrapper wrapper = new IDXAuthenticationWrapper(
                properties.getIssuer(),
                properties.getClientId(),
                properties.getClientSecret(),
                scopes,
                properties.getRedirectUri());

        installCookieAwareClient(wrapper, properties, scopes);

        return wrapper;
    }

    /**
     * IDXAuthenticationWrapper's own builder never exposes a way to swap in a custom OkHttpClient,
     * so there's no supported public API to (a) attach a DT cookie to every outgoing IDX request or
     * (b) turn on the underlying client's body-level wire logging - even though okta-http-okhttp
     * supports both (the latter via ClientConfiguration#setRequestExecutorParams(Map.of("debug",
     * "BODY"))). So we build a second IDXClient ourselves on top of a custom OkHttpClient and
     * reflectively swap it into the wrapper's private `client` field.
     * <p>
     * The DT cookie matters because okta-idx-java only ever sends the device token as an
     * X-Device-Token header (via RequestContext.setDeviceToken, see AuthController#loginForm), but
     * Okta's known-device check for the self-service-unlock flow only looks at a DT cookie - it
     * never reads that header.
     */
    private void installCookieAwareClient(IDXAuthenticationWrapper wrapper, OktaIdxProperties properties, Set<String> scopes) {
        try {
            ClientConfiguration clientConfiguration = new ClientConfiguration();
            clientConfiguration.setIssuer(properties.getIssuer());
            clientConfiguration.setClientId(properties.getClientId());
            clientConfiguration.setClientSecret(properties.getClientSecret());
            clientConfiguration.setScopes(scopes);
            clientConfiguration.setRedirectUri(properties.getRedirectUri());
            if (properties.isDebugHttp()) {
                clientConfiguration.setRequestExecutorParams(Map.of("debug", "BODY"));
            }

            OkHttpClient.Builder httpClientBuilder = new OkHttpClient.Builder()
                    .addInterceptor(chain -> {
                        Request request = chain.request();
                        Request.Builder requestBuilder = request.newBuilder()
                                .addHeader("X-Okta-User-Agent-Extended", "okta-auth-js/7.14.5 okta-signin-widget-7.49.0");
                        requestBuilder = addDeviceFingerprintHeadersAndCookies(request, requestBuilder);
                        requestBuilder = forceRememberMe(request, requestBuilder);
                        return chain.proceed(requestBuilder.build());
                    });

            RequestExecutor requestExecutor = new OkHttpRequestExecutorFactory(httpClientBuilder.build())
                    .create(clientConfiguration);

            Class<?> baseClientClass = Class.forName("com.okta.idx.sdk.api.client.BaseIDXClient");
            Constructor<?> constructor = baseClientClass.getDeclaredConstructor(ClientConfiguration.class, RequestExecutor.class);
            constructor.setAccessible(true);
            IDXClient customClient = (IDXClient) constructor.newInstance(clientConfiguration, requestExecutor);

            Field clientField = IDXAuthenticationWrapper.class.getDeclaredField("client");
            clientField.setAccessible(true);
            clientField.set(wrapper, customClient);

            if (properties.isDebugHttp()) {
                log.warn("okta.idx.debug-http is enabled: raw Okta HTTP request/response bodies " +
                        "(including plaintext password, client secret, and tokens) will be printed to the console.");
            }
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Failed to install cookie-aware Okta IDX HTTP client", e);
        }
    }

    static Request.Builder addDeviceFingerprintHeadersAndCookies(Request request, Request.Builder requestBuilder) {
        List<String> cookies = new ArrayList<>(request.headers().values("Cookie"));

        String deviceToken = CurrentDeviceToken.get();
        if (deviceToken != null && !deviceToken.isBlank()) {
            cookies.add(DT_COOKIE_NAME + "=" + deviceToken);
        }

        String deviceFingerprint = CurrentDeviceFingerprint.get();
        if (CurrentDeviceFingerprint.isValid(deviceFingerprint)) {
            cookies.add(CurrentDeviceFingerprint.COOKIE_NAME + "=" + deviceFingerprint);
            requestBuilder.header(CurrentDeviceFingerprint.COOKIE_NAME, deviceFingerprint);
        }

        if (!cookies.isEmpty()) {
            requestBuilder.header("Cookie", String.join("; ", cookies));
        }
        return requestBuilder;
    }

    /**
     * Rewrites {@code "rememberMe":false} to {@code "rememberMe":true} in the outgoing request
     * body, if present. Only identify requests carry this field, so the check is cheap and a no-op
     * for every other IDX call.
     */
    private static Request.Builder forceRememberMe(Request request, Request.Builder requestBuilder) throws java.io.IOException {
        RequestBody body = request.body();
        if (body == null || body.contentLength() == 0) {
            return requestBuilder;
        }

        Buffer buffer = new Buffer();
        body.writeTo(buffer);
        String bodyString = buffer.readString(StandardCharsets.UTF_8);

        if (!REMEMBER_ME_FALSE.matcher(bodyString).find()) {
            return requestBuilder;
        }

        String rewritten = REMEMBER_ME_FALSE.matcher(bodyString).replaceAll("\"rememberMe\":true");
        MediaType contentType = body.contentType();
        return requestBuilder.method(request.method(), RequestBody.create(rewritten, contentType));
    }
}
