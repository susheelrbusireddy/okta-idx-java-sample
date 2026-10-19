package com.okta.sample.idx.config;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import okhttp3.Interceptor;
import okhttp3.MediaType;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class IdxRemediationLoggingInterceptorTest {

    private static final MediaType IDX_MEDIA_TYPE = MediaType.parse("application/ion+json");

    @Test
    void logsEveryRemediationAsMetadataAndLeavesBodiesReadable() throws Exception {
        String identifyBody = """
                {"stateHandle":"state-secret","remediation":{"type":"array","value":[
                  {"name":"identify","type":"object","rel":["create-form"],"method":"POST",
                   "href":"https://example.okta.com/idp/idx/identify?token=href-secret",
                   "accepts":"application/json","produces":"application/ion+json",
                   "value":[
                     {"name":"identifier","label":"Username","type":"string","required":true,"value":"user-secret"},
                     {"name":"credentials","label":"Password","type":"object","required":true,"secret":true,"value":{"passcode":"password-secret"},
                      "options":[{"label":"Authenticator","value":"option-secret"}]},
                     {"name":"profile","type":"object","form":{"value":[{"name":"email","label":"Email","value":"nested-secret"}]}}
                   ]}
                ]}}
                """;
        String verifyBody = """
                {"stateHandle":"another-state-secret","remediation":{"type":"array","value":[
                  {"name":"challenge-authenticator","type":"object","method":"POST","href":"/idp/idx/challenge?state=href-secret",
                   "value":[{"name":"passcode","type":"string","required":true,"secret":true,"value":"verify-secret"}]}
                ]}}
                """;
        Request identifyRequest = request("/idp/idx/identify?request-secret=one");
        Request verifyRequest = request("/idp/idx/challenge?request-secret=two");
        Response identifyResponse = response(identifyRequest, identifyBody, "request-id-one");
        Response verifyResponse = response(verifyRequest, verifyBody, "request-id-two");
        Interceptor.Chain chain = mock(Interceptor.Chain.class);
        when(chain.request()).thenReturn(identifyRequest, verifyRequest);
        when(chain.proceed(any(Request.class))).thenReturn(identifyResponse, verifyResponse);

        Logger logger = (Logger) LoggerFactory.getLogger(IdxRemediationLoggingInterceptor.class);
        Level priorLevel = logger.getLevel();
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.setContext(logger.getLoggerContext());
        appender.start();
        logger.setLevel(Level.DEBUG);
        logger.addAppender(appender);
        try {
            Response loggedIdentify = new IdxRemediationLoggingInterceptor().intercept(chain);
            Response loggedVerify = new IdxRemediationLoggingInterceptor().intercept(chain);

            assertThat(loggedIdentify.body().string()).isEqualTo(identifyBody);
            assertThat(loggedVerify.body().string()).isEqualTo(verifyBody);

            String logs = appender.list.stream()
                    .map(ILoggingEvent::getFormattedMessage)
                    .collect(Collectors.joining("\n"));
            assertThat(logs)
                    .contains("request-id-one", "request-id-two", "/idp/idx/identify", "challenge-authenticator",
                            "name=credentials", "label=Password", "secret=true", "optionCount=1")
                    .doesNotContain("state-secret", "another-state-secret", "href-secret", "request-secret",
                            "user-secret", "password-secret", "option-secret", "nested-secret", "verify-secret");
        } finally {
            logger.detachAppender(appender);
            logger.setLevel(priorLevel);
            appender.stop();
        }
    }

    @Test
    void logsStructuredSdkErrorsWithoutMessageTextOrParameters() throws Exception {
        String body = """
                {"messages":{"type":"array","value":[
                   {"message":"private error for user@example.test","i18n":{"key":"errors.E0000004","params":["private-param"]},"value":"ERROR"}
                 ]},"stateHandle":"private-state"}
                """;
        Request request = request("/idp/idx/identify?private-query=value");
        Response response = response(request, body, "request-id-error");
        Interceptor.Chain chain = mock(Interceptor.Chain.class);
        when(chain.request()).thenReturn(request);
        when(chain.proceed(any(Request.class))).thenReturn(response);

        Logger logger = (Logger) LoggerFactory.getLogger(IdxRemediationLoggingInterceptor.class);
        Level priorLevel = logger.getLevel();
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.setContext(logger.getLoggerContext());
        appender.start();
        logger.setLevel(Level.DEBUG);
        logger.addAppender(appender);
        try {
            Response logged = new IdxRemediationLoggingInterceptor().intercept(chain);

            assertThat(logged.body().string()).isEqualTo(body);
            String logs = appender.list.stream()
                    .map(ILoggingEvent::getFormattedMessage)
                    .collect(Collectors.joining("\\n"));
            assertThat(logs)
                    .contains("request-id-error", "status=200", "errorCode=-", "classification=ERROR",
                            "i18nKey=errors.E0000004")
                    .doesNotContain("private-error-description", "private error for user@example.test",
                            "private-param", "private-state", "private-query=value");
        } finally {
            logger.detachAppender(appender);
            logger.setLevel(priorLevel);
            appender.stop();
        }
    }

    @Test
    void skipsOversizedBodiesWithoutConsumingThem() throws Exception {
        String body = "x".repeat(256 * 1024 + 1);
        Request request = request("/idp/idx/identify");
        Response response = response(request, body, "request-id-large");
        Interceptor.Chain chain = mock(Interceptor.Chain.class);
        when(chain.request()).thenReturn(request);
        when(chain.proceed(any(Request.class))).thenReturn(response);

        Response logged = new IdxRemediationLoggingInterceptor().intercept(chain);

        assertThat(logged.body().string()).isEqualTo(body);
    }

    private static Request request(String path) {
        return new Request.Builder().url("https://example.okta.com" + path).build();
    }

    private static Response response(Request request, String body, String requestId) {
        return response(request, body, requestId, 200);
    }

    private static Response response(Request request, String body, String requestId, int status) {
        return new Response.Builder()
                .request(request)
                .protocol(Protocol.HTTP_1_1)
                .code(status)
                .message(status == 200 ? "OK" : "Error")
                .header("X-Okta-Request-Id", requestId)
                .body(ResponseBody.create(body, IDX_MEDIA_TYPE))
                .build();
    }
}
