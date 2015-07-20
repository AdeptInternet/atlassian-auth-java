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

import java.security.Principal;
import java.util.Locale;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import static org.adeptnet.atlassian.common.Common.NEGOTIATE;
import static org.adeptnet.atlassian.common.Common.WWW_AUTHENTICATE;
import org.adeptnet.atlassian.saml.SAMLException;
import org.apache.commons.logging.Log;
import org.opensaml.ws.message.encoder.MessageEncodingException;

/**
 *
 * @author Francois Steyn - Adept Internet (PTY) LTD (francois.s@adept.co.za)
 */
public interface AuthenticatorInterface {

    Log getLog();

    Common getCommon() throws IllegalStateException;

    Principal getUser(final String userName);

    Principal getUserFromSession(final HttpServletRequest httpServletRequest);

    boolean authoriseUserAndEstablishSession(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse, final Principal principal);

    default public void doRedirect(final HttpServletRequest request, final HttpServletResponse response, final String relayState) {
        try {
            getCommon().doSAMLRedirect(request, response, relayState);
        } catch (MessageEncodingException | SAMLException ex) {
            getLog().fatal(ex.getMessage(), ex);
        }
    }

    default public Principal getUserFromUserName(final HttpServletRequest request, final HttpServletResponse response, final String userName, final String method) {
        final Log log = getLog();
        final Principal user = getUser(userName);
        if (user == null) {
            log.warn(String.format("User not found: %s", userName));
            return null;
        }
        log.info(String.format("Logged in %s via %s", user, method));
        if (!authoriseUserAndEstablishSession(request, response, user)) {
            log.warn(String.format("User not authorised: %s", userName));
            return null;
        }
        return user;
    }

    default public Principal getUserCommon(final HttpServletRequest request, final HttpServletResponse response) {
        final Principal userSession = getUserFromSession(request);
        if (userSession != null) {
            return userSession;
        }

        final Common common = getCommon();

        final String krb5User = common.getKrb5UserName(request);
        if (krb5User != null) {
            return getUserFromUserName(request, response, krb5User, "KRB5");
        }

        final String samlUser = common.getSAMLUserName(request);
        if (samlUser != null) {
            return getUserFromUserName(request, response, samlUser, "SAML");
        }

        if (response == null) {
            return null;
        }

        if (common.isKrb5Enabled()) {
            final String uri = request.getRequestURI().toLowerCase(Locale.UK);
            if (!common.krb5Skip401(uri)) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }
            response.setHeader(WWW_AUTHENTICATE, NEGOTIATE);
        }

        return null;
    }

}
