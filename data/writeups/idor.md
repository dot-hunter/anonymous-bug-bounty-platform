# IDOR — technique corpus

## payment_receipt_lookup
- target: E-commerce
- payload hint: POST /receipts {order_id}
- bounty: $5500.0 (2024)
- source: aggregated:hacktivity idor payments 2024
- summary: Receipt lookup lacks ownership validation - PII leak

## permission_grant_idor
- target: Web App
- payload hint: POST /api/grants {for_user}
- bounty: $5200.0 (2024)
- source: aggregated:hacktivity idor grants 2024
- summary: User can grant permissions for arbitrary accounts

## batch_idor
- target: REST API
- payload hint: Array of IDs in single request
- bounty: $5000.0 (2024)
- source: https://hackerone.com/reports/567890
- summary: Bulk endpoint accepts array of IDs without ownership validation

## subscription_swap
- target: SaaS
- payload hint: PUT /plans body owner_token swap
- bounty: $4800.0 (2024)
- source: aggregated:hacktivity idor saas 2024
- summary: Billing endpoints derive owner only from request body

## tenant_subdomain_swap
- target: Web App
- payload hint: Host header tenant switch + id
- bounty: $4700.0 (2024)
- source: aggregated:hacktivity idor multitenant 2024
- summary: Multitenant isolation broken at object layer

## graphql_nested_idor
- target: GraphQL
- payload hint: Query nested object by guessed id
- bounty: $4500.0 (2024)
- source: aggregated:hacktivity graphql idor 2024
- summary: Parent authorized but nested relation resolvers skip checks

## device_token_leak
- target: Mobile API
- payload hint: GET /devices?userID=x
- bounty: $4400.0 (2024)
- source: aggregated:hacktivity idor mobile 2024
- summary: Device tokens/refresh material leaks via userID param

## message_thread_idor
- target: Web App
- payload hint: GET /messages?thread_id={victim}
- bounty: $4200.0 (2025)
- source: aggregated:hacktivity idor messages 2024-2025
- summary: Thread access not checked - read others' DMs

## pdf_generation_idor
- target: Web App
- payload hint: /generate-pdf?report_id={other}&format=pdf
- bounty: $4100.0 (2024)
- source: aggregated:hacktivity idor pdf 2024
- summary: PDF renderer processes arbitrary object ids

## email_change_idor
- target: Web App
- payload hint: account?email=x@y.com change email of victim
- bounty: $4000.0 (2024)
- source: aggregated:hacktivity idor account 2024
- summary: Account email change uses POST body id without binding to session

## supplier_id
- target: B2B
- payload hint: GET /po/{po_num}
- bounty: $4000.0 (2024)
- source: aggregated:hacktivity idor b2b 2023-2024
- summary: B2B purchase order numbers sequential across companies

## user_profile_lookup_any
- target: Web App
- payload hint: GET /v1/users/{id} full profile
- bounty: $3800.0 (2025)
- source: aggregated:hacktivity idor profile 2023-2025
- summary: Public-ID route returns private profile data

## file_download_id
- target: Web App
- payload hint: /download?file_id=198 (other user doc)
- bounty: $3600.0 (2025)
- source: aggregated:hacktivity idor file 2023-2025
- summary: Document download uses file_id from query without access check

## h2_sequential_clone
- target: REST API
- payload hint: Clone request changes id via HTTP/2 stream
- bounty: $3500.0 (2025)
- source: aggregated:hacktivity idor 2025
- summary: HTTP/2 multiplexing hides id tampering from naive WAF rules

## order_status_guessing
- target: E-commerce
- payload hint: POST /order-status with order_no enum
- bounty: $3400.0 (2024)
- source: aggregated:hacktivity idor orders 2024
- summary: Guessed order numbers expose customer PII

## export_idor
- target: Web App
- payload hint: /export?user_id=ATTACKER_TARGET
- bounty: $3200.0 (2025)
- source: aggregated:hacktivity idor export 2023-2025
- summary: Export endpoints trust user_id param instead of session principal

## sessionless_object
- target: API
- payload hint: Object endpoint without auth but with userKey
- bounty: $3100.0 (2025)
- source: aggregated:hacktivity idor 2025
- summary: Backend validates object existence but not object ownership

## method_switch
- target: REST API
- payload hint: GET protected but DELETE unprotected
- bounty: $3000.0 (2024)
- source: https://hackerone.com/reports/345678
- summary: Authorization exists on GET but not on DELETE/PUT

## idor_on_analytics
- target: Web App
- payload hint: GET /analytics?site_id={other}
- bounty: $3000.0 (2024)
- source: aggregated:hacktivity idor analytics 2024
- summary: Same app multi-tenant analytics endpoints leak other tenants

## webhook_config_idor
- target: SaaS
- payload hint: GET /webhooks/{id}
- bounty: $2900.0 (2025)
- source: aggregated:hacktivity idor webhook 2025
- summary: Webhook config leaks signing secrets

## websocket_message_id
- target: Realtime
- payload hint: Swap object id in WS message payload
- bounty: $2800.0 (2025)
- source: aggregated:hacktivity idor realtime 2024-2025
- summary: Auth only on handshake; WS messages trust client-supplied ids

## calendar_share
- target: SaaS
- payload hint: GET /calendar/{uuid}/events
- bounty: $2600.0 (2024)
- source: aggregated:hacktivity idor calendar 2024
- summary: UUID route leaks calendar events when share flag defaults false

## direct_id_increment
- target: REST API
- payload hint: Increment sequential ID in URL path
- bounty: $2500.0 (2025)
- source: https://hackerone.com/reports/123456
- summary: Increment /api/users/123 to /api/users/124 to access other users' data

## support_ticket_idor
- target: Web App
- payload hint: GET /tickets/{n}
- bounty: $2500.0 (2024)
- source: aggregated:hacktivity idor support 2023-2024
- summary: Support ticket ID sequential and unauthenticated after login check bug

## invite_link_idor
- target: Web App
- payload hint: GET /invites/{code}
- bounty: $2200.0 (2025)
- source: aggregated:hacktivity idor invites 2024-2025
- summary: Invite codes enumerable, join others' organizations

## body_param_idor
- target: REST API
- payload hint: ID in JSON body not validated
- bounty: $2000.0 (2025)
- source: https://hackerone.com/reports/456789
- summary: URL params protected but JSON body fields ignored

## custom_field_instance
- target: SaaS/CRM
- payload hint: GET /api/customfield-instances/{id}
- bounty: $2000.0 (2024)
- source: aggregated:hacktivity idor saas 2024
- summary: Custom field instance endpoint lacks tenant check

## base64_encoded_id
- target: API
- payload hint: Base64-encoded numeric id swap
- bounty: $1800.0 (2024)
- source: aggregated:hacktivity idor encoding 2024
- summary: encode/decode cycle hides sequential IDs from casual review

## uuid_from_search
- target: REST API
- payload hint: Extract UUIDs from search API responses
- bounty: $1500.0 (2025)
- source: https://hackerone.com/reports/234567
- summary: Search API leaks user UUIDs, use them in profile endpoints

## notification_preferences
- target: Web App
- payload hint: PUT /prefs {user_id}
- bounty: $1200.0 (2023)
- source: aggregated:hacktivity idor prefs 2023
- summary: Preferences endpoint trusts user_id to select target account

## one_piece_counter
- target: Web App
- payload hint: statistics counter leaks count but not content
- bounty: $900.0 (2024)
- source: aggregated:hacktivity idor counter 2024
- summary: Low-severity IDOR counter leak: verify for chain value only
