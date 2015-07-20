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
package org.adeptnet.atlassian.confluence;

import com.atlassian.confluence.user.ConfluenceUser;
import com.atlassian.seraph.auth.AuthenticatorException;
import com.atlassian.seraph.config.SecurityConfig;
import java.security.Principal;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.adeptnet.atlassian.common.AuthenticatorInterface;
import org.adeptnet.atlassian.common.Common;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 *
 * @author Francois Steyn - Adept Internet (PTY) LTD (francois.s@adept.co.za)
 */
public class Authenticator extends com.atlassian.confluence.user.ConfluenceAuthenticator implements AuthenticatorInterface {

    private static final Log LOG = LogFactory.getLog(Authenticator.class);

    private static final long serialVersionUID = 20150101001L;

    private static final Common common = new Common();

    @Override
    protected Principal getUserFromBasicAuthentication(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse) {
        throw new UnsupportedOperationException("KRB5/SAML Enabled - Should not use getUserFromBasicAuthentication, check configuration");
    }

    @Override
    protected boolean authenticate(final Principal user, final String password) throws AuthenticatorException {
        throw new UnsupportedOperationException("KRB5/SAML Enabled - Should not use authenticate, check configuration");
    }

    @Override
    protected Principal getUserFromCookie(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse) {
        return null; //Must login via Kerberos
    }

    @Override
    public boolean login(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse, final String userName, final String password, final boolean setRememberMeCookie) throws AuthenticatorException {
        throw new UnsupportedOperationException("KRB5/SAML Enabled - Should not use login, check configuration: login is initiated by getUser() & Negotiate");
    }

    @Override
    public void init(final Map<String, String> params, final SecurityConfig config) {
        common.init(params);
        super.init(params, config);
    }

    @Override
    public Log getLog() {
        return LOG;
    }

    @Override
    public Common getCommon() throws IllegalStateException {
        return common.check();
    }

    @Override
    public Principal getUserFromSession(final HttpServletRequest httpServletRequest) {
        return super.getUserFromSession(httpServletRequest);
    }

    @Override
    public boolean authoriseUserAndEstablishSession(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse, final Principal principal) {
        return super.authoriseUserAndEstablishSession(httpServletRequest, httpServletResponse, principal); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public Principal getUser(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse) {
        return getUserCommon(httpServletRequest, httpServletResponse);
    }

    @Override
    public ConfluenceUser getUser(final String userName) {
        return super.getUser(userName);
    }
}
