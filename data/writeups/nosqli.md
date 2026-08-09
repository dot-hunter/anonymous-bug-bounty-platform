# NOSQLI — technique corpus

## mongodb_dump_chain
- target: NoSQL
- payload hint: $where to sys op (sys_* funcs)
- bounty: $7000.0 (2024)
- source: aggregated:hacktivity nosqli dump 2024
- summary: Where operator data dump

## nosql_to_ssrf
- target: NoSQL
- payload hint: $where JS fetch
- bounty: $5000.0 (2024)
- source: aggregated:hacktivity nosqli ssrf 2024
- summary: JS operator SSRF

## mongo_gt
- target: NoSQL
- payload hint: {"$where":"sleep(5)"}
- bounty: $4500.0 (2024)
- source: aggregated:hacktivity nosqli where 2024
- summary: $where operator

## mongo_ne
- target: NoSQL
- payload hint: {"username":{"$ne":"admin"},"password":{"$ne":"x"}}
- bounty: $4000.0 (2025)
- source: https://hackerone.com/reports/414141
- summary: MongoDB $ne operator bypasses authentication

## mongo_regex
- target: NoSQL
- payload hint: {"username":{"$regex":".*"}}
- bounty: $3500.0 (2024)
- source: https://hackerone.com/reports/424242
- summary: MongoDB regex injection extracts data

## session_cookie_payload
- target: NoSQL
- payload hint: session cookie objects
- bounty: $3300.0 (2024)
- source: aggregated:hacktivity nosqli session 2024
- summary: Session store injection

## dynamodb_condition
- target: NoSQL
- payload hint: attribute_not_exists control
- bounty: $3200.0 (2024)
- source: aggregated:hacktivity nosqli dynamo 2024
- summary: DynamoDB condition injection

## mongo_in_operator
- target: NoSQL
- payload hint: {"role":{"$in":["admin"]}}
- bounty: $3000.0 (2024)
- source: aggregated:hacktivity nosqli in 2024
- summary: $in array injection

## nosql_obj_init
- target: NoSQL
- payload hint: JSON body objects
- bounty: $2800.0 (2024)
- source: aggregated:hacktivity nosqli obj 2024
- summary: Object JSON injection

## blind_regex
- target: NoSQL
- payload hint: {"user":{"$regex":"^a.*"}}
- bounty: $2500.0 (2024)
- source: aggregated:hacktivity nosqli blind 2024
- summary: Blind regex enumeration

## nosqli_union_payload
- target: NoSQL
- payload hint: [$ne] + field exists
- bounty: $2000.0 (2024)
- source: aggregated:hacktivity nosqli exists 2024
- summary: $exists probing

## couchdb_doc
- target: NoSQL
- payload hint: CouchDB 2.x auth confusion
- bounty: $2000.0 (2024)
- source: aggregated:hacktivity nosqli couch 2024
- summary: CouchDB auth bypass

## redis_command
- target: NoSQL
- payload hint: redis key pattern via params
- bounty: $1800.0 (2024)
- source: aggregated:hacktivity nosqli redis 2024
- summary: Redis key enumeration

## extractor_via_jsonpath
- target: NoSQL
- payload hint: jsonpath injection
- bounty: $1700.0 (2024)
- source: aggregated:hacktivity nosqli jp 2024
- summary: JSONPath filter injection

## error_msg_data
- target: NoSQL
- payload hint: verbose error data
- bounty: $1200.0 (2024)
- source: aggregated:hacktivity nosqli error 2024
- summary: Error-based data

## hidden_field_bulk
- target: NoSQL
- payload hint: $unset fields
- bounty: $900.0 (2024)
- source: aggregated:hacktivity nosqli unset 2024
- summary: Unset field tampering

## query_dup_operator
- target: NoSQL
- payload hint: duplicate $ ops
- bounty: $800.0 (2024)
- source: aggregated:hacktivity nosqli dup 2024
- summary: Duplicated operator confusion

## return_first_match
- target: NoSQL
- payload hint: limit/flags
- bounty: $700.0 (2024)
- source: aggregated:hacktivity nosqli flags 2024
- summary: Return-all flags
