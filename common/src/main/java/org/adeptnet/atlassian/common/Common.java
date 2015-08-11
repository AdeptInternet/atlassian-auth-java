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
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.adeptnet.auth.kerberos.Krb5;
import org.adeptnet.auth.kerberos.Krb5ConfigImpl;
import org.adeptnet.auth.saml.AttributeSet;
import org.adeptnet.auth.saml.SAMLClient;
import org.adeptnet.auth.saml.SAMLConfigImpl;
import org.adeptnet.auth.saml.SAMLException;
import org.adeptnet.auth.saml.SAMLInit;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.ws.message.encoder.MessageEncodingException;

/**
 *
 * @author Francois Steyn - Adept Internet (PTY) LTD (francois.s@adept.co.za)
 */
public class Common {

    private static final Log LOG = LogFactory.getLog(Common.class);

    private final static String KRB5_ENABLE = "krb5-enable";
    private final static String KRB5_SKIP401 = "krb5-skip401";
    private final static String KRB5_REALM = "krb5-realm";
    private final static String KRB5_KEYTAB = "krb5-keytab";
    private final static String KRB5_LOGIN_CONTEXT = "krb5-login-context";
    private final static String SAML_ENABLE = "saml-enable";
    private final static String SAML_IDP_CONFIG = "saml-idp-config";
    private final static String SAML_SP_CONFIG = "saml-sp-config";
    private final static String SAML_KEYSTORE_NAME = "saml-keystore-name";
    private final static String SAML_KEYSTORE_PASSWORD = "saml-keystore-password";
    private final static String SAML_CERTIFICATE_ALIAS = "saml-certificate-alias";

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
        client.doSAMLRedirect(response, relayState);
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
        final String _ticket = request.getHeader(Krb5.AUTHORIZATION);
        if (_ticket == null) {
            return null;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Found Kerberos Ticket");
        }
        if (LOG.isTraceEnabled()) {
            LOG.trace(_ticket);
        }

        final String ticket = Krb5.extractTicket(_ticket);
        if (ticket == null) {
            return null;
        }

        final String serverName = Krb5.resolveServerName(request.getServerName());

        krb5Cfg.init(getFileName(request.getServletContext()));
        final String realm = String.format("@%s", krb5Cfg.getRealm());
        final String spn = String.format("HTTP/%s%s", serverName, realm);
        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("SPN: %s", spn));
        }
        final String username = new Krb5(krb5Cfg).isTicketValid(spn, Base64.getDecoder().decode(ticket));

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
        final String samlTicket = request.getParameter(SAMLClient.SAML_RESPONSE);
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
            final SAMLClient client = getSAMLClient(request.getServletContext());
            if ("GET".equalsIgnoreCase(request.getMethod())) {
                aset = client.validateResponseGET(request.getQueryString());
            } else {
                aset = client.validateResponsePOST(samlTicket);
            }
        } catch (SAMLException ex) {
            LOG.fatal(ex.getMessage(), ex);
            return null;
        }
        return aset.getNameId();
    }

    public boolean krb5Skip401(final String uri) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(String.format("krb5Skip401: %s", uri));
        }
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
