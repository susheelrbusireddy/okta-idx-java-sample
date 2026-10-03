package com.okta.sample.idx.config;

import com.okta.commons.http.RequestExecutor;
import com.okta.commons.http.okhttp.OkHttpRequestExecutorFactory;
import com.okta.idx.sdk.api.client.IDXAuthenticationWrapper;
import com.okta.idx.sdk.api.client.IDXClient;
import com.okta.idx.sdk.api.config.ClientConfiguration;
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
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Configuration
@EnableConfigurationProperties(OktaIdxProperties.class)
public class OktaIdxConfig {

    private static final Logger log = LoggerFactory.getLogger(OktaIdxConfig.class);

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
     * IDXAuthenticationWrapper's own builder never exposes a way to swap in a custom OkHttpClient, so there is no
     * supported public API to turn on the underlying client's body-level wire logging - even though okta-http-okhttp
     * supports it via ClientConfiguration#setRequestExecutorParams(Map.of("debug", "BODY")). So we build a second
     * IDXClient ourselves on top of a custom OkHttpClient and reflectively swap it into the wrapper's private
     * `client` field.
     * <p>
     * The interceptor deliberately adds nothing that a plain okta-idx-java client would not send: the device token
     * goes out only as the X-Device-Token header the SDK itself sets (see AuthController#loginForm). Earlier versions
     * of this sample also spoofed an okta-auth-js user agent and replayed DT / X-Device-Fingerprint cookies to work
     * around OKTA-1281722; that made the sample take Okta's Sign-In-Widget code paths instead of the SDK ones, so it
     * could no longer reproduce what a real confidential-client SDK sees.
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
                        Request.Builder requestBuilder = forceRememberMe(request, request.newBuilder());
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
