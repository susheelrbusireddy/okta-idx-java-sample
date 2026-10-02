package com.okta.sample.idx.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "okta.idx")
public class OktaIdxProperties {

    private String issuer;
    private String clientId;
    private String clientSecret;
    private String scopes;
    private String redirectUri;
    private boolean debugHttp;

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getScopes() {
        return scopes;
    }

    public void setScopes(String scopes) {
        this.scopes = scopes;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public boolean isDebugHttp() {
        return debugHttp;
    }

    public void setDebugHttp(boolean debugHttp) {
        this.debugHttp = debugHttp;
    }
}
