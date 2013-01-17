#!/usr/bin/python

import sys
from xml.dom.minidom import parse, parseString
spring_doc = parse(sys.argv[1])
top_element = spring_doc.documentElement
sso_provider = parseString("""\
<beans:beans
 xmlns="http://www.springframework.org/schema/security"
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xmlns:beans="http://www.springframework.org/schema/beans"
   xmlns:sec="http://www.springframework.org/schema/security"
   xsi:schemaLocation="
                http://www.springframework.org/schema/security
                http://www.springframework.org/schema/security/spring-security-3.1.xsd
                http://www.springframework.org/schema/beans
                http://www.springframework.org/schema/beans/spring-beans-3.1.xsd">
<authentication-manager alias="authenticationManager">
   <authentication-provider ref="userAuthenticationProvider" />
</authentication-manager>
<beans:bean id="userAuthenticationProvider"
         class="com.vmware.bdd.security.UserAuthenticationProvider">
   <beans:property name="userService" ref="userService" />
</beans:bean>
</beans:beans>
""")
old_auth_manager = top_element.getElementsByTagName('authentication-manager')
top_element.removeChild(old_auth_manager[0])
old_beans = top_element.getElementsByTagName('beans:bean')
for bean in old_beans:
   if bean.getAttribute('id') == 'userAuthenticationProvider':
      top_element.removeChild(bean)
new_auth_manager = sso_provider.documentElement.getElementsByTagName('authentication-manager')
top_element.appendChild(new_auth_manager[0])
new_beans = sso_provider.documentElement.getElementsByTagName('beans:bean')
for bean in new_beans:
   top_element.appendChild(bean)
print spring_doc.toprettyxml("  ", "")
