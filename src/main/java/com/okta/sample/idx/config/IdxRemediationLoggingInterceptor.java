package com.okta.sample.idx.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.Interceptor;
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

final class IdxRemediationLoggingInterceptor implements Interceptor {

    private static final Logger log = LoggerFactory.getLogger(IdxRemediationLoggingInterceptor.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final long MAX_LOG_BODY_BYTES = 256 * 1024;
    private static final Pattern CONTROL_CHARACTERS = Pattern.compile("\\p{Cntrl}");
    private static final int MAX_LOG_VALUE_LENGTH = 160;

    @Override
    public Response intercept(Chain chain) throws IOException {
        Request request = chain.request();
        Response response = chain.proceed(request);
        boolean debugEnabled = log.isDebugEnabled();
        boolean httpError = response.code() >= 400;
        if (!debugEnabled && !httpError) {
            return response;
        }

        ResponseBody responseBody = response.body();
        if (responseBody == null || !isJson(responseBody.contentType())) {
            if (httpError) {
                logErrorResponse(request, response, "-", null);
            }
            return response;
        }
        if (responseBody.contentLength() > MAX_LOG_BODY_BYTES) {
            if (httpError) {
                logErrorResponse(request, response, "-", null);
            }
            log.debug("Skipping IDX remediation logging for oversized response: method={} path={} status={}",
                    request.method(), request.url().encodedPath(), response.code());
            return response;
        }

        byte[] body;
        try {
            body = response.peekBody(MAX_LOG_BODY_BYTES + 1).bytes();
        } catch (IOException e) {
            if (httpError) {
                logErrorResponse(request, response, "-", null);
            }
            log.debug("Skipping IDX remediation logging for unreadable response: method={} path={} status={}",
                    request.method(), request.url().encodedPath(), response.code());
            return response;
        }
        if (body.length > MAX_LOG_BODY_BYTES) {
            if (httpError) {
                logErrorResponse(request, response, "-", null);
            }
            log.debug("Skipping IDX remediation logging for oversized response: method={} path={} status={}",
                    request.method(), request.url().encodedPath(), response.code());
            return response;
        }

        JsonNode responseJson;
        try {
            responseJson = OBJECT_MAPPER.readTree(body);
        } catch (IOException e) {
            if (httpError) {
                logErrorResponse(request, response, "-", null);
            }
            log.debug("Skipping IDX remediation logging for non-JSON response: method={} path={} status={}",
                    request.method(), request.url().encodedPath(), response.code());
            return response;
        }

        JsonNode remediations = responseJson.path("remediation").path("value");
        JsonNode messages = responseJson.path("messages").path("value");
        String errorCode = safeCode(responseJson.path("error"));
        boolean sdkError = hasSdkError(messages);
        if (httpError || sdkError || !"-".equals(errorCode)) {
            logErrorResponse(request, response, errorCode, messages);
        }
        if (!debugEnabled || !remediations.isArray()) {
            return response;
        }

        String requestId = safeString(response.header("X-Okta-Request-Id"));
        String requestPath = safeString(request.url().encodedPath());
        log.debug("IDX response: requestId={} method={} status={} path={} remediationCount={}",
                requestId, request.method(), response.code(), requestPath, remediations.size());

        for (int i = 0; i < remediations.size(); i++) {
            JsonNode remediation = remediations.get(i);
            String name = safeText(remediation.path("name"));
            log.debug("IDX remediation: requestId={} index={} name={} type={} rel={} method={} hrefPath={} accepts={} produces={} refresh={}",
                    requestId,
                    i,
                    name,
                    safeText(remediation.path("type")),
                    safeRelation(remediation.path("rel")),
                    safeText(remediation.path("method")),
                    safePath(safeText(remediation.path("href"))),
                    safeText(remediation.path("accepts")),
                    safeText(remediation.path("produces")),
                    safeText(remediation.path("refresh")));
            logFormFields(requestId, name, remediation.path("value"));
        }

        return response;
    }

    private static void logErrorResponse(Request request, Response response, String errorCode, JsonNode messages) {
        String requestId = safeString(response.header("X-Okta-Request-Id"));
        int messageCount = messages != null && messages.isArray() ? messages.size() : 0;
        log.error("Okta SDK error response: requestId={} method={} status={} path={} errorCode={} messageCount={}",
                requestId, request.method(), response.code(), safeString(request.url().encodedPath()), errorCode, messageCount);

        if (messages == null || !messages.isArray()) {
            return;
        }
        for (int i = 0; i < messages.size(); i++) {
            JsonNode message = messages.get(i);
            log.error("Okta SDK error detail: requestId={} index={} classification={} i18nKey={}",
                    requestId, i, safeCode(message.path("value")), i18nKey(message));
        }
    }

    private static boolean hasSdkError(JsonNode messages) {
        if (!messages.isArray()) {
            return false;
        }
        for (JsonNode message : messages) {
            if ("ERROR".equals(message.path("value").asText())) {
                return true;
            }
        }
        return false;
    }

    private static String i18nKey(JsonNode message) {
        JsonNode i18n = message.path("i18n");
        if (i18n.isMissingNode()) {
            i18n = message.path("i18NMessage");
        }
        if (i18n.isMissingNode()) {
            i18n = message.path("i18nMessage");
        }
        return safeCode(i18n.path("key"));
    }

    private static String safeCode(JsonNode value) {
        String code = safeText(value);
        return code.matches("[A-Za-z0-9_.:-]{1,160}") ? code : "-";
    }

    private static boolean isJson(MediaType contentType) {
        if (contentType == null) {
            return false;
        }
        String subtype = contentType.subtype().toLowerCase(Locale.ROOT);
        return "json".equals(subtype) || subtype.endsWith("+json");
    }

    private static void logFormFields(String requestId, String remediationName, JsonNode fields) {
        if (!fields.isArray()) {
            return;
        }
        for (int i = 0; i < fields.size(); i++) {
            JsonNode field = fields.get(i);
            JsonNode options = field.path("options");
            log.debug("IDX remediation field: requestId={} remediation={} index={} name={} label={} type={} required={} secret={} visible={} mutable={} optionCount={}",
                    requestId,
                    remediationName,
                    i,
                    safeText(field.path("name")),
                    safeText(field.path("label")),
                    safeText(field.path("type")),
                    safeText(field.path("required")),
                    safeText(field.path("secret")),
                    safeText(field.path("visible")),
                    safeText(field.path("mutable")),
                    options.isArray() ? options.size() : 0);
            logFormFields(requestId, remediationName, field.path("form").path("value"));
        }
    }

    private static String safeRelation(JsonNode relation) {
        if (!relation.isArray()) {
            return safeText(relation);
        }
        List<String> values = new ArrayList<>(relation.size());
        relation.forEach(value -> values.add(safeText(value)));
        return String.join(",", values);
    }

    private static String safeText(JsonNode value) {
        return value == null || value.isMissingNode() || value.isNull() ? "-" : safeString(value.asText());
    }

    private static String safeString(String value) {
        if (value == null) {
            return "-";
        }
        String sanitized = CONTROL_CHARACTERS.matcher(value).replaceAll(" ").trim();
        return sanitized.length() > MAX_LOG_VALUE_LENGTH
                ? sanitized.substring(0, MAX_LOG_VALUE_LENGTH)
                : sanitized;
    }

    private static String safePath(String href) {
        if ("-".equals(href)) {
            return "-";
        }
        try {
            String path = URI.create(href).getRawPath();
            return safeString(path == null ? "-" : path);
        } catch (IllegalArgumentException e) {
            return "[invalid]";
        }
    }
}
