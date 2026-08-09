# PROTOTYPE_POLLUTION — technique corpus

## pp_to_rce
- target: Node.js
- payload hint: execArgv pollution
- bounty: $20000.0 (2025)
- source: https://hackerone.com/reports/404041
- summary: Prototype pollution escalates to RCE via child_process options

## childprocess_rce
- target: Node
- payload hint: options TTYS/execArgv
- bounty: $18000.0 (2024)
- source: aggregated:hacktivity pp cp 2024
- summary: child_process option PP

## pug_compile
- target: Node
- payload hint: pug options PP RCE
- bounty: $16000.0 (2024)
- source: aggregated:hacktivity pp pug 2024
- summary: Pug PP RCE

## ejs_payload
- target: Node
- payload hint: EJS vulnerable options
- bounty: $15000.0 (2024)
- source: aggregated:hacktivity pp ejs 2024
- summary: EJS PP RCE

## ssrf_via_pp
- target: Node
- payload hint: PP to modify fetch URL dest
- bounty: $9000.0 (2024)
- source: aggregated:hacktivity pp ssrf 2024
- summary: PP → SSRF

## config_override
- target: Node
- payload hint: config pollution to auth bypass
- bounty: $6000.0 (2024)
- source: aggregated:hacktivity pp auth 2024
- summary: Config override PP

## constructor_prototype
- target: Node
- payload hint: constructor.prototype
- bounty: $5200.0 (2024)
- source: aggregated:hacktivity pp ctor 2024
- summary: constructor.proto path

## json_merge
- target: Node.js
- payload hint: {"__proto__":{"polluted":true}}
- bounty: $5000.0 (2025)
- source: https://hackerone.com/reports/383838
- summary: JSON body merges into Object prototype via vulnerable merge

## yaml_unsafe
- target: Node
- payload hint: yaml.load PP
- bounty: $5000.0 (2024)
- source: aggregated:hacktivity pp yaml 2024
- summary: yaml unsafe load PP

## qs_oss_factory
- target: Node
- payload hint: qs 6.9 delta parser
- bounty: $4800.0 (2024)
- source: aggregated:hacktivity pp qs 2024
- summary: qs parser PP

## lodash_deep_merge
- target: Node
- payload hint: lodash merge
- bounty: $4700.0 (2024)
- source: aggregated:hacktivity pp lodash 2024
- summary: lodash merge PP

## query_merge
- target: Node.js
- payload hint: __proto__[isAdmin]=true
- bounty: $4500.0 (2024)
- source: https://hackerone.com/reports/393939
- summary: Query params merged via defaults-deep => prototype pollution

## protocol_pollution_utility
- target: Node
- payload hint: merge deepcopy libs
- bounty: $4500.0 (2024)
- source: aggregated:hacktivity pp lib 2024
- summary: deep-merge PP

## json5_merge
- target: Node
- payload hint: JSON5 with __proto__
- bounty: $4100.0 (2024)
- source: aggregated:hacktivity pp json5 2024
- summary: JSON5 parser PP

## minimist_options
- target: Node
- payload hint: argv parsing _ proto
- bounty: $4000.0 (2024)
- source: aggregated:hacktivity pp minimist 2024
- summary: minimist PP

## filter_whitelist
- target: Node
- payload hint: __proto__ bypass via filtered key
- bounty: $3800.0 (2024)
- source: aggregated:hacktivity pp bypass 2024
- summary: Bypassing key filtering

## express_params
- target: Node
- payload hint: express query merged into body
- bounty: $3500.0 (2024)
- source: aggregated:hacktivity pp express 2024
- summary: Express merge PP

## array_pop_chain
- target: Node
- payload hint: length pollution
- bounty: $3300.0 (2024)
- source: aggregated:hacktivity pp array 2024
- summary: Array length PP

## prototype_pollution_web3
- target: Browser
- payload hint: window.pp via merge in frontend
- bounty: $2900.0 (2024)
- source: aggregated:hacktivity pp browser 2024
- summary: Browser PP XSS

## event_emitter_abuse
- target: Node
- payload hint: prototype listener
- bounty: $2500.0 (2024)
- source: aggregated:hacktivity pp ee 2024
- summary: EventEmitter prototype
