# JWT — technique corpus

## kid_injection
- target: API
- payload hint: kid pointing to attacker file
- bounty: $7000.0 (2025)
- source: https://hackerone.com/reports/272727
- summary: kid header injects arbitrary file path as signing key

## alg_family_switch
- target: API
- payload hint: ES256→HS256 verified via public key
- bounty: $5200.0 (2024)
- source: aggregated:hacktivity jwt es 2024
- summary: EC key confusion

## rs256_hs256
- target: API
- payload hint: RS256->HS256 confusion
- bounty: $5000.0 (2024)
- source: https://hackerone.com/reports/262626
- summary: Public key used as HMAC secret to forge tokens

## refresh_token_reuse
- target: API
- payload hint: refresh token rotation ignored
- bounty: $4800.0 (2024)
- source: aggregated:hacktivity jwt refresh 2024
- summary: Refresh token reuse

## jku_whitelist
- target: API
- payload hint: jku header to attacker URL
- bounty: $4200.0 (2024)
- source: aggregated:hacktivity jwt jku 2024
- summary: JKU confusion

## jwk_injection
- target: API
- payload hint: jwk inline attacker key
- bounty: $3600.0 (2024)
- source: aggregated:hacktivity jwt jwk 2024
- summary: JWK header trust

## aud_confusion
- target: API
- payload hint: aud not checked multi-tenant
- bounty: $3300.0 (2024)
- source: aggregated:hacktivity jwt aud 2024
- summary: Audience confusion

## alg_none
- target: API
- payload hint: alg:none header bypass
- bounty: $3000.0 (2025)
- source: https://hackerone.com/reports/252525
- summary: Server accepts alg:none JWT and trusts unsigned payload

## jwt_in_cookie_double
- target: API
- payload hint: validation in middleware vs route
- bounty: $3000.0 (2024)
- source: aggregated:hacktivity jwt middleware 2024
- summary: Double validation mismatch

## none_with_kid
- target: API
- payload hint: kid favicon + none
- bounty: $2800.0 (2024)
- source: aggregated:hacktivity jwt none 2024
- summary: Ignored alg verification

## weak_secret
- target: API
- payload hint: Hashcat crack of weak HMAC secret
- bounty: $2500.0 (2024)
- source: https://hackerone.com/reports/282828
- summary: Weak JWT signing secret cracked in seconds

## iss_claim_ignore
- target: API
- payload hint: iss ignored - token reuse cross-service
- bounty: $2500.0 (2024)
- source: aggregated:hacktivity jwt iss 2024
- summary: ISS mismatch

## client_secret_leak
- target: API
- payload hint: JWT logs raw secret
- bounty: $2200.0 (2024)
- source: aggregated:hacktivity jwt secret 2024
- summary: Secret disclosed

## jwt_via_refresh_flow
- target: API
- payload hint: refresh batching
- bounty: $2000.0 (2024)
- source: aggregated:hacktivity jwt 2024
- summary: Refresh race

## decoder_confusion
- target: API
- payload hint: JWS→JWE decode issue
- bounty: $1600.0 (2024)
- source: aggregated:hacktivity jwt jwe 2024
- summary: Encrypted token decode confusion

## bridging_alg_ec
- target: API
- payload hint: ES256 k value reuse
- bounty: $1500.0 (2024)
- source: aggregated:hacktivity jwt ec 2024
- summary: EC nonce reuse

## expiry_skip
- target: API
- payload hint: exp not checked
- bounty: $1000.0 (2024)
- source: aggregated:hacktivity jwt exp 2024
- summary: Expired token accepted

## partial_signature
- target: API
- payload hint: trailing garbage accepted
- bounty: $900.0 (2024)
- source: aggregated:hacktivity jwt partial 2024
- summary: Partial signature tolerance

## nbf_validation_skip
- target: API
- payload hint: nbf not checked
- bounty: $800.0 (2024)
- source: aggregated:hacktivity jwt nbf 2024
- summary: nbf accepts future tokens

## jwt_in_qs
- target: API
- payload hint: token in URL logging
- bounty: $700.0 (2024)
- source: aggregated:hacktivity jwt qs 2024
- summary: Token in query logs
