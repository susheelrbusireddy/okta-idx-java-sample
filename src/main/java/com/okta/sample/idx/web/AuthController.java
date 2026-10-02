package com.okta.sample.idx.web;

import com.okta.idx.sdk.api.client.Authenticator;
import com.okta.idx.sdk.api.client.IDXAuthenticationWrapper;
import com.okta.idx.sdk.api.client.ProceedContext;
import com.okta.idx.sdk.api.model.AuthenticationOptions;
import com.okta.idx.sdk.api.model.AuthenticationStatus;
import com.okta.idx.sdk.api.model.FormValue;
import com.okta.idx.sdk.api.model.Options;
import com.okta.idx.sdk.api.model.RequestContext;
import com.okta.idx.sdk.api.model.VerifyAuthenticatorOptions;
import com.okta.idx.sdk.api.request.IdentifyRequest;
import com.okta.idx.sdk.api.response.AuthenticationResponse;
import com.okta.idx.sdk.api.response.TokenResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.okta.sample.idx.devicetoken.CurrentDeviceFingerprint;
import com.okta.sample.idx.devicetoken.CurrentDeviceToken;
import com.okta.sample.idx.service.ClaimsService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;

import java.net.URI;
import java.time.Duration;
import java.util.List;

@Controller
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private static final String PROCEED_CONTEXT = "proceedContext";
    private static final String PENDING_AUTHENTICATORS = "pendingAuthenticators";
    private static final String ID_CLAIMS = "idClaims";
    private static final String ACCESS_CLAIMS = "accessClaims";
    private static final String RAW_ID_TOKEN = "rawIdToken";
    private static final String RAW_ACCESS_TOKEN = "rawAccessToken";

    private final IDXAuthenticationWrapper idx;
    private final ClaimsService claimsService;

    public AuthController(IDXAuthenticationWrapper idx, ClaimsService claimsService) {
        this.idx = idx;
        this.claimsService = claimsService;
    }

    @GetMapping("/")
    public String home() {
        return "redirect:/login";
    }

    @GetMapping("/login")
    public String loginForm(HttpSession session, Model model) {
        if (!CurrentDeviceFingerprint.isValid(CurrentDeviceFingerprint.get())) {
            session.removeAttribute(PROCEED_CONTEXT);
            model.addAttribute("needsDeviceFingerprint", true);
            return "login";
        }

        model.addAttribute("needsDeviceFingerprint", false);
        RequestContext requestContext = new RequestContext();
        String deviceToken = CurrentDeviceToken.get();
        if (deviceToken != null && !deviceToken.isBlank()) {
            requestContext.setDeviceToken(deviceToken);
        }

        AuthenticationResponse beginResponse = idx.begin(requestContext);
        logResponse("begin", beginResponse);
        session.setAttribute(PROCEED_CONTEXT, beginResponse.getProceedContext());
        log.info("next screen: login");
        return "login";
    }

    @PostMapping(value = "/device-fingerprint", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Void> storeDeviceFingerprint(@RequestParam("visitorId") String visitorId,
                                                        HttpServletRequest request) {
        if (!isSameOrigin(request)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
        if (!CurrentDeviceFingerprint.isValid(visitorId)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }

        ResponseCookie cookie = ResponseCookie.from(CurrentDeviceFingerprint.COOKIE_NAME, visitorId)
                .httpOnly(true)
                .secure(request.isSecure())
                .path("/")
                .maxAge(Duration.ofDays(CurrentDeviceFingerprint.COOKIE_MAX_AGE_DAYS))
                .sameSite("Lax")
                .build();
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .build();
    }

    private static boolean isSameOrigin(HttpServletRequest request) {
        String originHeader = request.getHeader("Origin");
        if (originHeader == null) {
            return false;
        }

        try {
            URI origin = URI.create(originHeader);
            if (origin.getScheme() == null || origin.getHost() == null
                    || origin.getRawPath() == null || !origin.getRawPath().isEmpty()
                    || origin.getRawQuery() != null || origin.getRawFragment() != null) {
                return false;
            }
            return origin.getScheme().equalsIgnoreCase(request.getScheme())
                    && origin.getHost().equalsIgnoreCase(request.getServerName())
                    && effectivePort(origin) == request.getServerPort();
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static int effectivePort(URI uri) {
        if (uri.getPort() >= 0) {
            return uri.getPort();
        }
        if ("https".equalsIgnoreCase(uri.getScheme())) {
            return 443;
        }
        if ("http".equalsIgnoreCase(uri.getScheme())) {
            return 80;
        }
        return -1;
    }

    private static boolean hasDeviceFingerprint() {
        return CurrentDeviceFingerprint.isValid(CurrentDeviceFingerprint.get());
    }

    @PostMapping("/login")
    public String login(@RequestParam String username,
                         @RequestParam String password,
                         HttpSession session,
                         Model model) {
        ProceedContext proceedContext = (ProceedContext) session.getAttribute(PROCEED_CONTEXT);
        if (proceedContext == null || !hasDeviceFingerprint()) {
            return "redirect:/login";
        }

        AuthenticationOptions options = new AuthenticationOptions(username, password.toCharArray());
        AuthenticationResponse response = idx.authenticate(options, proceedContext);
        return handleResponse(response, session, model, "login");
    }

    @PostMapping("/mfa/select")
    public String selectAuthenticator(@RequestParam String authenticatorId,
                                       HttpSession session,
                                       Model model) {
        ProceedContext proceedContext = (ProceedContext) session.getAttribute(PROCEED_CONTEXT);
        @SuppressWarnings("unchecked")
        List<Authenticator> authenticators = (List<Authenticator>) session.getAttribute(PENDING_AUTHENTICATORS);

        if (proceedContext == null || authenticators == null || !hasDeviceFingerprint()) {
            return "redirect:/login";
        }

        Authenticator chosen = authenticators.stream()
                .filter(a -> a.getId().equals(authenticatorId))
                .findFirst()
                .orElse(null);

        if (chosen == null) {
            model.addAttribute("authenticators", authenticators);
            model.addAttribute("errors", List.of("Unknown authenticator selected"));
            return "mfa-select";
        }

        AuthenticationResponse response = idx.selectAuthenticator(proceedContext, chosen);
        return handleResponse(response, session, model, "mfa-select");
    }

    @PostMapping("/mfa/verify")
    public String verify(@RequestParam String code, HttpSession session, Model model) {
        ProceedContext proceedContext = (ProceedContext) session.getAttribute(PROCEED_CONTEXT);
        if (proceedContext == null || !hasDeviceFingerprint()) {
            return "redirect:/login";
        }

        AuthenticationResponse response = idx.verifyAuthenticator(proceedContext, new VerifyAuthenticatorOptions(code));
        return handleResponse(response, session, model, "mfa-verify");
    }

    @GetMapping("/claims")
    public String claims(HttpSession session, Model model) {
        Object idClaims = session.getAttribute(ID_CLAIMS);
        if (idClaims == null) {
            return "redirect:/login";
        }

        model.addAttribute("idClaims", idClaims);
        model.addAttribute("accessClaims", session.getAttribute(ACCESS_CLAIMS));
        model.addAttribute("rawIdToken", session.getAttribute(RAW_ID_TOKEN));
        model.addAttribute("rawAccessToken", session.getAttribute(RAW_ACCESS_TOKEN));
        return "claims";
    }

    @PostMapping("/logout")
    public String logout(HttpSession session) {
        session.invalidate();
        return "redirect:/login";
    }

    /**
     * Branches to the next screen purely based on what Okta's IDX response says happens next.
     */
    private String handleResponse(AuthenticationResponse response, HttpSession session, Model model, String retryView) {
        logResponse(retryView, response);
        session.setAttribute(PROCEED_CONTEXT, response.getProceedContext());

        if (response.getErrors() != null && !response.getErrors().isEmpty()) {
            model.addAttribute("errors", response.getErrors());
            restoreRetryViewState(retryView, session, model);
            log.info("next screen: {} (redisplayed after error)", retryView);
            return retryView;
        }

        AuthenticationStatus status = response.getAuthenticationStatus();
        if (status == null) {
            status = AuthenticationStatus.UNKNOWN;
        }

        String nextView;
        switch (status) {
            case SUCCESS:
                nextView = handleSuccess(response, session);
                break;

            case AWAITING_AUTHENTICATOR_SELECTION:
            case AWAITING_AUTHENTICATOR_ENROLLMENT_SELECTION:
                session.setAttribute(PENDING_AUTHENTICATORS, response.getAuthenticators());
                model.addAttribute("authenticators", response.getAuthenticators());
                nextView = "mfa-select";
                break;

            case AWAITING_AUTHENTICATOR_VERIFICATION:
            case AWAITING_AUTHENTICATOR_VERIFICATION_DATA:
                nextView = "mfa-verify";
                break;

            default:
                model.addAttribute("status", status);
                model.addAttribute("errors", response.getErrors());
                nextView = "status";
                break;
        }

        log.info("next screen: {} (decided from status={})", nextView, status);
        return nextView;
    }

    private String handleSuccess(AuthenticationResponse response, HttpSession session) {
        TokenResponse tokenResponse = response.getTokenResponse();
        session.setAttribute(ID_CLAIMS, claimsService.decode(tokenResponse.getIdToken()));
        session.setAttribute(ACCESS_CLAIMS, claimsService.decode(tokenResponse.getAccessToken()));
        session.setAttribute(RAW_ID_TOKEN, tokenResponse.getIdToken());
        session.setAttribute(RAW_ACCESS_TOKEN, tokenResponse.getAccessToken());
        return "redirect:/claims";
    }

    private void restoreRetryViewState(String retryView, HttpSession session, Model model) {
        if ("mfa-select".equals(retryView)) {
            model.addAttribute("authenticators", session.getAttribute(PENDING_AUTHENTICATORS));
        }
    }

    private void logResponse(String step, AuthenticationResponse response) {
        log.info("===== Okta IDX response [{}] =====", step);
        log.info("status: {}", response.getAuthenticationStatus());

        if (response.getErrors() != null && !response.getErrors().isEmpty()) {
            log.info("errors: {}", response.getErrors());
            log.info("errors getAuthenticationStatus: {}", response.getAuthenticationStatus());
            log.info("errors getProceedContext: {}", response.getProceedContext());
            log.info("errors getTokenResponse: {}", response.getTokenResponse());
        }

        try {
            log.info("full response object: {}", OBJECT_MAPPER.writeValueAsString(response));
        } catch (Exception e) {
            log.info("full response object: (failed to serialize: {})", e.getMessage());
        }

        if (response.getAuthenticators() != null && !response.getAuthenticators().isEmpty()) {
            response.getAuthenticators().forEach(a ->
                    log.info("available authenticator: id={} label={} type={}", a.getId(), a.getLabel(), a.getType()));
        }

        log.info("remediation form fields (only populated by this SDK during profile enrollment/sign-up):");
        logFormValues(response.getFormValues(), "  ");

        TokenResponse tokenResponse = response.getTokenResponse();
        if (tokenResponse != null) {
            log.info("tokenResponse: tokenType={} scope={} expiresIn={}",
                    tokenResponse.getTokenType(), tokenResponse.getScope(), tokenResponse.getExpiresIn());
            log.info("idToken: {}", tokenResponse.getIdToken());
            log.info("accessToken: {}", tokenResponse.getAccessToken());
        }
    }

    /**
     * Recursively prints the "remediation" form Okta returned - i.e. the field names/types/required
     * flags the SDK expects the client to submit for whatever the next step is (identify, select an
     * authenticator, answer a challenge, etc).
     */
    private void logFormValues(List<FormValue> formValues, String indent) {
        if (formValues == null || formValues.isEmpty()) {
            log.info("{}(no form fields on this response)", indent);
            return;
        }

        for (FormValue field : formValues) {
            log.info("{}field: name={} label={} type={} required={} value={}",
                    indent, field.getName(), field.getLabel(), field.type, field.isRequired(), field.getValue());

            if (field.getForm() != null && field.getForm().getValue() != null) {
                logFormValues(field.getForm().getValue(), indent + "  ");
            }

            List<Options> options = field.options();
            if (options != null && !options.isEmpty()) {
                for (Options option : options) {
                    log.info("{}  option: label={} value={}", indent, option.getLabel(), option.getValue());
                }
            }
        }
    }
}
