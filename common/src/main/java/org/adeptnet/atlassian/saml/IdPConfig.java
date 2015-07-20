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
package org.adeptnet.atlassian.saml;

import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;

import java.io.File;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;

import org.opensaml.Configuration;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.common.xml.SAMLConstants;

import javax.xml.bind.DatatypeConverter;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * IdpConfig contains information about the SAML 2.0 Identity Provider that
 * authenticates users for a service. Generally, it will be initialized by
 * loading the metadata file from disk.
 */
public class IdPConfig {

    /**
     * Default constructor. Applications may use this if the configuration
     * information comes from some outside source.
     */
    public IdPConfig() {
    }

    /**
     * Construct a new IdpConfig from a metadata XML file.
     *
     * @param metadataFile File where the matadata lives
     * @throws org.adeptnet.atlassian.saml.SAMLException
     */
    public IdPConfig(File metadataFile) throws SAMLException {
        final BasicParserPool parsers = new BasicParserPool();
        parsers.setNamespaceAware(true);

        final EntityDescriptor edesc;

        try {
            final Document doc = parsers.parse(new FileInputStream(metadataFile));
            final Element root = doc.getDocumentElement();

            final UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();

            edesc = (EntityDescriptor) unmarshallerFactory
                    .getUnmarshaller(root)
                    .unmarshall(root);
        } catch (org.opensaml.xml.parse.XMLParserException | org.opensaml.xml.io.UnmarshallingException | java.io.IOException e) {
            throw new SAMLException(e);
        }

        // fetch idp information
        final IDPSSODescriptor idpDesc = edesc.getIDPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol");

        if (idpDesc == null) {
            throw new SAMLException("No IDP SSO descriptor found");
        }

        // get the http-redirect binding
        String _loginUrl = null;
        for (SingleSignOnService svc : idpDesc.getSingleSignOnServices()) {
            if (svc.getBinding().equals(SAMLConstants.SAML2_REDIRECT_BINDING_URI)) {
                _loginUrl = svc.getLocation();
                break;
            }
        }

        if (_loginUrl == null) {
            throw new SAMLException("No acceptable Single Sign-on Service found");
        }

        // extract the first signing cert from the file
        Certificate _cert = null;

        find_cert_loop:
        for (KeyDescriptor kdesc : idpDesc.getKeyDescriptors()) {
            if (kdesc.getUse() != UsageType.SIGNING) {
                continue;
            }

            KeyInfo ki = kdesc.getKeyInfo();
            if (ki == null) {
                continue;
            }

            for (X509Data x509data : ki.getX509Datas()) {
                for (X509Certificate xcert : x509data.getX509Certificates()) {
                    try {
                        _cert = certFromString(xcert.getValue());
                        break find_cert_loop;
                    } catch (CertificateException e) {
                        // keep trying certs; if we don't have one we'll
                        // throw a SAMLException at the end.
                    }
                }
            }
        }
        if (_cert == null) {
            throw new SAMLException("No valid signing cert found");
        }

        this.setEntityId(edesc.getEntityID());
        this.setLoginUrl(_loginUrl);
        this.setCert(_cert);
    }

    private Certificate certFromString(String b64data) throws CertificateException {
        byte[] decoded = DatatypeConverter.parseBase64Binary(b64data);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return cf.generateCertificate(new ByteArrayInputStream(decoded));
    }

    /**
     * To whom requests are addressed
     */
    private String entityId;

    /**
     * Where the AuthnRequest is sent (SSOLoginService endpoint)
     */
    private String loginUrl;

    /**
     * Certificate used to validate assertions
     */
    private Certificate cert;

    /**
     * Set the Idp Entity Id.
     */
    public void setEntityId(final String entityId) {
        this.entityId = entityId;
    }

    /**
     * Get the Idp Entity Id.
     */
    public String getEntityId() {
        return this.entityId;
    }

    /**
     * Set the IdP login URL. The login URL is where the user is redirected from
     * the SP to initiate the authentication process.
     */
    public void setLoginUrl(final String loginUrl) {
        this.loginUrl = loginUrl;
    }

    /**
     * Get the IdP login URL.
     */
    public String getLoginUrl() {
        return this.loginUrl;
    }

    /**
     * Set the IdP public key certificate. The certificate is used to validate
     * signatures in the assertion.
     */
    public void setCert(final Certificate cert) {
        this.cert = cert;
    }

    /**
     * Get the Idp public key certificate.
     */
    public Certificate getCert() {
        return this.cert;
    }
}
