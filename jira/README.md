# Atlassian JIRA Kerberos/SAML Plugin
Authentication plugin for Atlassian JIRA using Kerberos / SAML

## [Example config](src/main/example/)
### [login.jsp](src/main/example/login.jsp)
Forces Kerberos / SAML Authentication
### [saml_acs.jsp](src/main/example/saml_acs.jsp)
Verify SAML Login
### [saml_login.jsp](src/main/example/saml_login.jsp)
Redirect to SAML Server
### [seraph-config.xml](src/main/example/seraph-config.xml)
Enable the plugin
### [server.example.com-idp-metadata.xml](src/main/example/server.example.com-idp-metadata.xml)
Example IDP Provider metadata
### [server.example.com-sp-metadata.xml](src/main/example/server.example.com-sp-metadata.xml)
Example SP metadata
### log4j.properties
```
#org.adeptnet logging
log4j.logger.org.adeptnet=INFO, console, filelog
```

## Credits
- https://github.com/lastpass/jira-saml
