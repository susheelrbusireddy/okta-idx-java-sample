# Okta IDX Java Auth Sample

A minimal Spring Boot app demonstrating username + password sign-in on a single screen using the
[okta-idx-java](https://github.com/okta/okta-idx-java) SDK (Okta Identity Engine / Interaction Code flow).
After the credentials are submitted, the next screen is chosen purely from Okta's response — success,
an MFA challenge, or any other remediation Okta returns.

## Prerequisites

- Java 17+
- Maven
- An Okta org running the **Identity Engine** (the IDX SDK requires OIE, not classic orgs)
- An OIDC app integration in that org with the **Interaction Code** grant type enabled

If you don't have the Okta app yet:

1. In the Okta Admin Console, go to **Applications > Create App Integration**.
2. Choose **OIDC - OpenID Connect**, application type **Web Application**.
3. Under **Grant type**, enable **Interaction Code** (in addition to any others you need).
4. Set a sign-in redirect URI, e.g. `http://localhost:8080/login/callback`.
5. Save, then copy the **Client ID**, **Client secret**, and your **Issuer** (Okta domain + `/oauth2/default`,
   or a custom authorization server).

## Configure

Edit [src/main/resources/application.yml](src/main/resources/application.yml):

```yaml
okta:
  idx:
    issuer: https://{yourOktaDomain}/oauth2/default
    client-id: "{clientId}"
    client-secret: "{clientSecret}"
    scopes: openid,profile,email,offline_access
    redirect-uri: http://localhost:8080/login/callback
```

## Run

```bash
mvn spring-boot:run
```

Then open `http://localhost:8080/login`.

## Flow

1. **`/login`** — enter username and password together and submit.
2. Depending on Okta's response:
   - **Success** — redirected straight to `/claims`.
   - **MFA required** — shown a list of available authenticators (`/mfa/select`), then a code entry
     screen (`/mfa/verify`) for authenticators like email/SMS OTP.
   - **Anything else** (password expired, profile enrollment, invalid credentials, etc.) — shown a
     status page with Okta's message, or the login form again with the error.
3. **`/claims`** — on success, shows the decoded claims from both the ID token and access token, plus
   the raw token strings.
4. **Sign Out** invalidates the session and returns to `/login`.

## Scope of this sample

This demonstrates response-driven branching for the most common cases (success, invalid credentials,
and one round of authenticator-based MFA). It does not implement every possible IDX remediation
(password recovery, profile enrollment, WebAuthn, etc.) — those statuses fall through to a generic
"additional step required" page instead of a dedicated flow.
