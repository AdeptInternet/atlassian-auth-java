/*
 * Copyright 2015 Francois Steyn - Adept Internet (PTY) LTD (francois.s@adept.co.za).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.adeptnet.atlassian.common;

import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import javax.naming.NamingException;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.adeptnet.atlassian.kerberos.Krb5;
import org.adeptnet.atlassian.kerberos.Krb5ConfigImpl;
import org.adeptnet.atlassian.saml.AttributeSet;
import org.adeptnet.atlassian.saml.SAMLClient;
import org.adeptnet.atlassian.saml.SAMLConfigImpl;
import org.adeptnet.atlassian.saml.SAMLException;
import org.adeptnet.atlassian.saml.SAMLInit;
import org.adeptnet.atlassian.saml.SAMLUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.impl.SingleSignOnServiceBuilder;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;

/**
 *
 * @author Francois Steyn - Adept Internet (PTY) LTD (francois.s@adept.co.za)
 */
public class Common {

    private static final Log LOG = LogFactory.getLog(Common.class);

    public static final String CREDS = "javax.security.auth.useSubjectCredsOnly";
    public static final String WWW_AUTHENTICATE = "WWW-Authenticate";
    public static final String AUTHORIZATION = "Authorization";
    public static final String NEGOTIATE = "Negotiate";
    public static final String SAML_RESPONSE = "SAMLResponse";

    public final static String KRB5_ENABLE = "krb5-enable";
    public final static String KRB5_SKIP401 = "krb5-skip401";
    public final static String KRB5_REALM = "krb5-realm";
    public final static String KRB5_KEYTAB = "krb5-keytab";
    public final static String KRB5_LOGIN_CONTEXT = "krb5-login-context";
    public final static String SAML_ENABLE = "saml-enable";
    public final static String SAML_IDP_CONFIG = "saml-idp-config";
    public final static String SAML_SP_CONFIG = "saml-sp-config";
    public final static String SAML_KEYSTORE_NAME = "saml-keystore-name";
    public final static String SAML_KEYSTORE_PASSWORD = "saml-keystore-password";
    public final static String SAML_CERTIFICATE_ALIAS = "saml-certificate-alias";

    private final Krb5ConfigImpl krb5Cfg = new Krb5ConfigImpl();

    private SAMLClient samlClient;
    private final SAMLConfigImpl samlCfg = new SAMLConfigImpl();
    private final List<Pattern> patterns = new ArrayList<>();

    private boolean hasInit;

    private boolean krb5Enabled;
    private boolean samlEnabled;

    public Common() {
    }

    public Common check() throws IllegalStateException {
        if (!hasInit) {
            throw new IllegalStateException("Please INIT before use");
        }
        return this;
    }

    private void initSkip401(final Map<String, String> params) {
        if (!params.containsKey(KRB5_SKIP401)) {
            return;
        }
        final String[] skips = params.get(KRB5_SKIP401).split("\n");
        for (final String _skip : skips) {
            final String skip = _skip.trim();
            if (skip.isEmpty()) {
                continue;
            }
            try {
                final Pattern pattern = Pattern.compile(skip);
                patterns.add(pattern);
            } catch (PatternSyntaxException ex) {
                LOG.error(String.format("skip401: %s - %s", skip, ex.getMessage()), ex);
            }
        }
    }

    public void init(final Map<String, String> params) {
        krb5Enabled = Boolean.valueOf(params.get(KRB5_ENABLE));
        initSkip401(params);
        krb5Cfg.setRealm(params.get(KRB5_REALM));
        if (params.containsKey(KRB5_KEYTAB)) {
            krb5Cfg.setKeytabName(params.get(KRB5_KEYTAB));
        }
        if (params.containsKey(KRB5_LOGIN_CONTEXT)) {
            krb5Cfg.setContextName(params.get(KRB5_LOGIN_CONTEXT));
        }

        samlEnabled = Boolean.valueOf(params.get(SAML_ENABLE));
        samlCfg.setIdpConfigName(params.get(SAML_IDP_CONFIG));
        samlCfg.setSpConfigName(params.get(SAML_SP_CONFIG));
        samlCfg.setKeystoreName(params.get(SAML_KEYSTORE_NAME));
        samlCfg.setKeystorePassword(params.get(SAML_KEYSTORE_PASSWORD));
        samlCfg.setCertificateAlias(params.get(SAML_CERTIFICATE_ALIAS));
        if (LOG.isDebugEnabled()) {
            LOG.debug(params);
            LOG.debug(String.format("krb5Enabled: %s", krb5Enabled));
            LOG.debug(String.format("samlEnabled: %s", samlEnabled));
        }

        hasInit = true;
    }

    private SAMLClient getSAMLClient(final ServletContext servletContext) throws SAMLException {
        if (samlClient == null) {
            SAMLInit.initialize();
            samlCfg.init(getFileName(servletContext));
            samlClient = new SAMLClient(samlCfg);
        }
        return samlClient;
    }

    public void doSAMLRedirect(final HttpServletRequest request, final HttpServletResponse response, final String relayState) throws SAMLException, MessageEncodingException {
        if (!samlEnabled) {
            throw new SAMLException("SAML is not enabled");
        }

        final SAMLClient client = getSAMLClient(request.getServletContext());
        final String requestId = SAMLUtils.generateRequestId();
        final AuthnRequest authnRequest = client.createAuthnRequest(requestId);

        final HttpServletResponseAdapter responseAdapter = new HttpServletResponseAdapter(response, true);
        final BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject> context = new BasicSAMLMessageContext<>();
        final Endpoint endpoint = new SingleSignOnServiceBuilder().buildObject();
        endpoint.setLocation(client.getIdPConfig().getLoginUrl());
        context.setPeerEntityEndpoint(endpoint);
        context.setOutboundSAMLMessage(authnRequest);
        context.setOutboundSAMLMessageSigningCredential(authnRequest.getSignature().getSigningCredential());
        context.setOutboundMessageTransport(responseAdapter);
        context.setRelayState(relayState == null ? "/" : relayState);

        final HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();

        encoder.encode(context);
    }

    private String normalize(final String data) {
        if (data.isEmpty()) {
            return data;
        }
        if (data.endsWith(".")) {
            return normalize(data.substring(0, data.length() - 1));
        }
        return data;
    }

    private String recurseResolveToA(final Nameserver ns, final Set<String> checked, final String host) throws NamingException {
        if (checked.contains(host)) {
            throw new NamingException(String.format("Recursive Name Lookup: %s", checked));
        }
        final String[] clookup = ns.lookup(host, "cname");
        if (clookup.length != 0) {
            checked.add(host);
            return recurseResolveToA(ns, checked, normalize(clookup[0]));
        }

        return host;
    }

    private Function<String, String> getFileName(final ServletContext servletContext) {
        return (fileName) -> {
            return servletContext.getRealPath(fileName);
        };
    }

    public String getKrb5UserName(final HttpServletRequest request) {
        if (!krb5Enabled) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("!krb5Enabled");
            }
            return null;
        }
        final String _ticket = request.getHeader(AUTHORIZATION);
        if (_ticket == null) {
            return null;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Found Kerberos Ticket");
        }
        if (LOG.isTraceEnabled()) {
            LOG.trace(_ticket);
        }
        if (!System.getProperties().containsKey(CREDS)) {
            LOG.warn(String.format("Setting [%s] to false", CREDS));
            System.setProperty(CREDS, "false");
        }

        final String[] ticketParts = _ticket.split(" ");
        if ((ticketParts.length != 2)
                || (!NEGOTIATE.equals(ticketParts[0]))) {
            LOG.error(String.format("Invalid KRB5 Ticket: %s", _ticket));
            return null;
        }

        final String serverName;
        try {
            serverName = recurseResolveToA(new Nameserver(), new HashSet<>(), request.getServerName());
        } catch (NamingException ex) {
            LOG.error(String.format("Cannot Resolve %s - %s", request.getServerName(), ex.getMessage()), ex);
            return null;
        }

        final byte[] ticket = Base64.getDecoder().decode(ticketParts[1]);
        krb5Cfg.init(getFileName(request.getServletContext()));
        final String realm = String.format("@%s", krb5Cfg.getRealm());
        final String spn = String.format("HTTP/%s%s", serverName, realm);
        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("SPN: %s", spn));
        }
        final String username = new Krb5(krb5Cfg).isTicketValid(spn, ticket);

        if (username == null || !username.endsWith(realm)) {
            LOG.error(String.format("Invalid username: %s", username));
            return null;
        }

        return username.split("@")[0];
    }

    public String getSAMLUserName(final HttpServletRequest request) {
        if (!samlEnabled) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("!samlEnabled");
            }
            return null;
        }
        final String samlTicket = request.getParameter(SAML_RESPONSE);
        if (samlTicket == null) {
            return null;
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Found SAML Ticket");
        }
        if (LOG.isTraceEnabled()) {
            LOG.trace(samlTicket);
        }
        final AttributeSet aset;
        try {
            aset = getSAMLClient(request.getServletContext()).validateResponse(samlTicket);
        } catch (SAMLException ex) {
            LOG.fatal(ex.getMessage(), ex);
            return null;
        }
        return aset.getNameId();
    }

    public boolean krb5Skip401(final String uri) {
        for (final Pattern pattern : patterns) {
            if (pattern.matcher(uri).matches()) {
                return true;
            }
        }
        return false;
    }

    public boolean isKrb5Enabled() {
        return krb5Enabled;
    }

    public boolean isSamlEnabled() {
        return samlEnabled;
    }

}
