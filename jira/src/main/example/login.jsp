<%@ page import="com.atlassian.jira.component.ComponentAccessor" %>
<%@ page import="com.atlassian.jira.ComponentManager" %>
<%@ page import="com.atlassian.jira.security.JiraAuthenticationContext" %>
<%@ taglib uri="webwork" prefix="ww" %>
<%@ taglib prefix="page" uri="sitemesh-page" %>
<html>
<head>
	<title><ww:text name="'common.words.login.caps'"/></title>
    <meta name="decorator" content="login" />
	<%
    final JiraAuthenticationContext jiraAuthenticationContext = ComponentManager.getComponentInstanceOfType(JiraAuthenticationContext.class);
    final boolean hasUser = jiraAuthenticationContext.getLoggedInUser() != null;
    if (hasUser) { %>
    <meta http-equiv="Refresh" content="0; url=/">
	<%  }
	%>
</head>
<body>
	<% if (hasUser) { %>
	<h1>Redirecting to <a href="/">home</a><h1>
	<% } else { %>
	<page:applyDecorator id="saml-login-form" name="auiform">
	    <page:param name="action"><%= request.getContextPath() %>/saml_login.jsp?<%= request.getQueryString() %></page:param>
	    <page:param name="method">post</page:param>
    	<page:param name="submitButtonName">login</page:param>
    	<page:param name="submitButtonText">Log In with SAML</page:param>
	</page:applyDecorator>
	<% } %>
</body>
</html>