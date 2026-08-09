# OAUTH — technique corpus

## redirect_uri_bypass
- target: OAuth
- payload hint: redirect_uri not strictly validated
- bounty: $3000.0 (2025)
- source: https://hackerone.com/reports/505050
- summary: Authorization code sent to attacker-controlled domain

## implicit_to_code_downgrade
- target: OAuth
- payload hint: response_type=code & flow downgrades
- bounty: $3000.0 (2024)
- source: aggregated:hacktivity oauth downgrade 2024
- summary: Implicit flow preferred when code unsupported

## jwk_header_confusion
- target: OIDC
- payload hint: jwk in header sets verification key
- bounty: $3000.0 (2024)
- source: aggregated:hacktivity jwt jwk 2024
- summary: JKU/JWK allow attacker keys

## subdomain_capture
- target: OAuth
- payload hint: redirect_uri on capturable subdomain
- bounty: $2800.0 (2024)
- source: aggregated:hacktivity subdomain 2024
- summary: redirect_uri subdomain available for takeover

## pkce_absence
- target: OAuth
- payload hint: Public client without PKCE
- bounty: $2500.0 (2025)
- source: https://hackerone.com/reports/707070
- summary: Mobile app OAuth flow missing PKCE allows code interception

## client_credential_scope
- target: OAuth
- payload hint: client_credentials huge scope
- bounty: $2200.0 (2024)
- source: aggregated:hacktivity oauth scope 2024
- summary: Client creds allow unauthorized scope

## state_csrf
- target: OAuth
- payload hint: Missing state parameter = CSRF
- bounty: $2000.0 (2024)
- source: https://hackerone.com/reports/606060
- summary: OAuth flow without state allows account linking CSRF

## custom_param_injection
- target: OAuth
- payload hint: extra query params carved into redirect_uri
- bounty: $2000.0 (2024)
- source: aggregated:hacktivity oauth 2024
- summary: Additional params ignored then echoed in redirect

## regex_anchor_missing
- target: OAuth
- payload hint: redirect_uri=https://target.com.evil.com/
- bounty: $1800.0 (2024)
- source: aggregated:hacktivity oauth regex 2024
- summary: Regex missing ^/$ anchors

## openid_nonce_reuse
- target: OIDC
- payload hint: nonce validation
- bounty: $1700.0 (2024)
- source: aggregated:hacktivity oidc nonce 2024
- summary: Nonce not verified -> replay attacks

## resource_owner_enum
- target: OAuth
- payload hint: POST /oauth/token with attacker creds returns different errors
- bounty: $1500.0 (2024)
- source: aggregated:hacktivity oauth enum 2024
- summary: User enumeration in password grant

## unbound_callback
- target: OAuth
- payload hint: callback URL mirrors arbitrary host
- bounty: $1500.0 (2024)
- source: aggregated:hacktivity oauth callback 2024
- summary: Callback host may be set to attacker-controlled value

## token_leak_referrer
- target: OAuth
- payload hint: token passed in Referer via image
- bounty: $1400.0 (2024)
- source: aggregated:hacktivity oauth referrer 2023-2024
- summary: Access token leaks via Referer on redirect pages

## client_auth_switch
- target: OAuth
- payload hint: client_secret_basic vs post confusion
- bounty: $1300.0 (2024)
- source: aggregated:hacktivity oauth client 2024
- summary: client_secret_auth method swaps auth

## trailing_slash
- target: OAuth
- payload hint: redirect_uri=https://target.com.evil/
- bounty: $1200.0 (2024)
- source: aggregated:hacktivity oauth parser 2024
- summary: Tailing slash + same-path bypass

## state_nonce_reuse
- target: OAuth
- payload hint: state reuse across sessions
- bounty: $1200.0 (2024)
- source: aggregated:hacktivity csrf oauth 2024
- summary: State reused - request Csrf leak only

## mfa_not_forced
- target: OAuth
- payload hint: login via OAuth 2.0 device flow without MFA
- bounty: $1100.0 (2024)
- source: aggregated:hacktivity oauth mfa 2024
- summary: OAuth device flow bypasses MFA enforcement

## oauth_flow_token_type
- target: OAuth
- payload hint: gin token_type=bearer confusion
- bounty: $900.0 (2024)
- source: aggregated:hacktivity oauth token 2024
- summary: token_type header ignored allows lower-scope tokens

## token_redirect_history
- target: OAuth
- payload hint: History access token in URL
- bounty: $900.0 (2023)
- source: aggregated:hacktivity oauth history 2023
- summary: Token in URL appears in browser history

## open_redirect_oauth
- target: OAuth
- payload hint: '/' to unknown domain
- bounty: $600.0 (2024)
- source: aggregated:hacktivity redirect switch 2024
- summary: Open redirect through OAuth error endpoints
