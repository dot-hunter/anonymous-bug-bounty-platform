# GRAPHQL — technique corpus

## aliasing_idor
- target: GraphQL
- payload hint: Aliased queries enumerate objects
- bounty: $4000.0 (2024)
- source: https://hackerone.com/reports/131313
- summary: Field aliases used to access other users' objects in a single query

## mutation_auth_skip
- target: GraphQL
- payload hint: mutation without auth for dangerous op
- bounty: $3200.0 (2024)
- source: aggregated:hacktivity graphql mfa 2024
- summary: Mutation endpoint omits auth

## ws_subscription_auth
- target: GraphQL
- payload hint: subscription w/ no auth
- bounty: $3000.0 (2024)
- source: aggregated:hacktivity graphql ws 2024
- summary: WebSocket subscription auth skip → data leak

## graphql_idor_objects
- target: GraphQL
- payload hint: id input direct object query
- bounty: $2800.0 (2024)
- source: aggregated:hacktivity graphql idor 2024
- summary: Object-level access without ownership

## rape_introspection_fields
- target: GraphQL
- payload hint: query of sensitive fields via introspection
- bounty: $2500.0 (2024)
- source: aggregated:hacktivity graphql sensitive 2024
- summary: Introspection exposes sensitive field names

## template_query
- target: GraphQL
- payload hint: union/generic queries map to many tables
- bounty: $2400.0 (2024)
- source: aggregated:hacktivity graphql union 2024
- summary: Generic unions expose database shape

## graphql_to_ssrf
- target: GraphQL
- payload hint: scalar URL input to fetch
- bounty: $2100.0 (2024)
- source: aggregated:hacktivity graphql ssrf 2024
- summary: Custom scalar URL fetch → SSRF

## batching_dos
- target: GraphQL
- payload hint: Hundreds of batched queries
- bounty: $2000.0 (2025)
- source: https://hackerone.com/reports/141414
- summary: No query batching limit allows resource exhaustion

## apollo_viewer conf
- target: GraphQL
- payload hint: request context confusion
- bounty: $1900.0 (2024)
- source: aggregated:hacktivity graphql context 2024
- summary: Apollo Server context identity confusion

## subscription_injection
- target: GraphQL
- payload hint: subscription topic from args
- bounty: $1800.0 (2025)
- source: aggregated:hacktivity graphql sub 2025
- summary: Topic name injection into channel

## cost_analysis_bypass
- target: GraphQL
- payload hint: complexity cost fields underestimates
- bounty: $1600.0 (2024)
- source: aggregated:hacktivity graphql cost 2024
- summary: Cost analysis can be beaten with deeper nesting

## introspection_enabled
- target: GraphQL
- payload hint: query { __schema { types { name } } }
- bounty: $1500.0 (2025)
- source: https://hackerone.com/reports/121212
- summary: Introspection enabled exposes full schema

## dynamic_arguments
- target: GraphQL
- payload hint: arguments[0] exploits
- bounty: $1500.0 (2024)
- source: aggregated:hacktivity graphql args 2024
- summary: Dynamic argument object injection

## persisted_query_bypass
- target: GraphQL
- payload hint: persisted query ID brute
- bounty: $1300.0 (2024)
- source: aggregated:hacktivity graphql pq 2024
- summary: Persisted query hash without allowlist

## alias_orchestration
- target: GraphQL
- payload hint: alias sequence to bypass rate limiting
- bounty: $1100.0 (2024)
- source: aggregated:hacktivity graphql ratelimit 2024
- summary: Aliading bypass of rate controls

## depth_attack
- target: GraphQL
- payload hint: Deep nested queries crash backend
- bounty: $1000.0 (2024)
- source: https://hackerone.com/reports/151515
- summary: No depth limit on nested query resolution

## deferred_query
- target: GraphQL
- payload hint: defer differences in handling
- bounty: $1000.0 (2024)
- source: aggregated:hacktivity graphql defer 2024
- summary: @defer handling might bypass limits

## graphql_errors_leak
- target: GraphQL
- payload hint: error messages include SQL
- bounty: $900.0 (2024)
- source: aggregated:hacktivity graphql errors 2024
- summary: Verbose errors

## introspection_woffle
- target: GraphQL
- payload hint: sniff via error differences
- bounty: $800.0 (2024)
- source: aggregated:hacktivity graphql enum 2024
- summary: Field suggestion leaks (clairvoyance)

## interface_implementation_confusion
- target: GraphQL
- payload hint: impl scanning
- bounty: $800.0 (2024)
- source: aggregated:hacktivity graphql impl 2024
- summary: Interface vs concrete type confusion

## fragment_dos
- target: GraphQL
- payload hint: super deep fragments
- bounty: $700.0 (2024)
- source: aggregated:hacktivity graphql frag 2024
- summary: Fragment recursion DoS

## query_id_reuse
- target: GraphQL
- payload hint: POST {queryId}
- bounty: $600.0 (2025)
- source: aggregated:hacktivity graphql pq 2025
- summary: Persisted query reuse across users
