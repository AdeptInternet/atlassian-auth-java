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

import org.opensaml.Configuration;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;

import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Attribute;

import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.validation.ValidationException;
import org.opensaml.xml.XMLObject;

import org.joda.time.DateTime;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSSerializer;
import org.xml.sax.InputSource;
import java.io.StringReader;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.UnsupportedEncodingException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import java.util.HashMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.Deflater;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import javax.xml.XMLConstants;

import javax.xml.bind.DatatypeConverter;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.adeptnet.atlassian.common.Common;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.Init;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.ws.transport.http.HTTPTransportUtils;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.SigningUtil;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.w3c.dom.DOMException;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

/**
 * A SAMLClient acts as on behalf of a SAML Service Provider to generate
 * requests and process responses.
 *
 * To integrate a service, one must generally do the following:
 *
 * 1. Change the login process to call generateAuthnRequest() to get a request
 * and link, and then GET/POST that to the IdP login URL.
 *
 * 2. Create a new URL that acts as the AssertionConsumerService -- it will call
 * validateResponse on the response body to verify the assertion; on success it
 * will use the subject as the authenticated user for the web application.
 *
 * The specific changes needed to the application are outside the scope of this
 * SDK.
 */
public class SAMLClient {

    private static final Log LOG = LogFactory.getLog(SAMLClient.class);

    private final SAMLConfig config;
    private final SignatureValidator sigValidator;
    private final BasicParserPool parsers;
    private final Credential cred;

    /* do date comparisons +/- this many seconds */
    private static final int slack = 300;

    private final Map<String, String> map = new HashMap<>();

    /**
     * Create a new SAMLClient, using the IdPConfig for endpoints and
     * validation.
     *
     * @param config
     * @throws org.adeptnet.atlassian.saml.SAMLException
     */
    public SAMLClient(final SAMLConfig config) throws SAMLException {
        this.config = config;

        final BasicCredential _cred = new BasicCredential();
        _cred.setEntityId(config.getIdPConfig().getEntityId());
        _cred.setPublicKey(config.getIdPConfig().getCert().getPublicKey());
        cred = _cred;

        sigValidator = new SignatureValidator(cred);

        // create xml parsers
        parsers = new BasicParserPool();
        parsers.setNamespaceAware(true);
    }

    /**
     * Get the configured IdpConfig.
     *
     * @return the IdPConfig associated with this client
     */
    public IdPConfig getIdPConfig() {
        return config.getIdPConfig();
    }

    /**
     * Get the configured SPConfig.
     *
     * @return the SPConfig associated with this client
     */
    public SPConfig getSPConfig() {
        return config.getSPConfig();
    }

    private Response parseResponse(String authnResponse) throws SAMLException {
        try {
            final Document doc = parsers.getBuilder()
                    .parse(new InputSource(new StringReader(authnResponse)));

            final Element root = doc.getDocumentElement();
            return (Response) Configuration.getUnmarshallerFactory()
                    .getUnmarshaller(root)
                    .unmarshall(root);
        } catch (org.opensaml.xml.parse.XMLParserException | org.opensaml.xml.io.UnmarshallingException | org.xml.sax.SAXException | java.io.IOException e) {
            throw new SAMLException(e);
        }
    }

    private void validatePOST(final Response response) throws ValidationException {
        // signature must match our SP's signature.
        final Signature sig1 = response.getSignature();
        sigValidator.validate(sig1);
        validate(response);
    }

    private void validate(final Response response) throws ValidationException {
        if (response.getStatus() == null
                || response.getStatus().getStatusCode() == null
                || !(StatusCode.SUCCESS_URI
                .equals(response.getStatus().getStatusCode().getValue()))) {
            throw new ValidationException("Response has an unsuccessful status code");
        }

        // response destination must match ACS
        if (!config.getSPConfig().getAcs().equals(response.getDestination())) {
            throw new ValidationException("Response is destined for a different endpoint");
        }

        final DateTime now = DateTime.now();

        // issue instant must be within a day
        final DateTime issueInstant = response.getIssueInstant();

        if (issueInstant != null) {
            if (issueInstant.isBefore(now.minusDays(1).minusSeconds(slack))) {
                throw new ValidationException("Response IssueInstant is in the past");
            }

            if (issueInstant.isAfter(now.plusDays(1).plusSeconds(slack))) {
                throw new ValidationException("Response IssueInstant is in the future");
            }
        }

        for (Assertion assertion : response.getAssertions()) {

            // Assertion must be signed correctly
            if (!assertion.isSigned()) {
                throw new ValidationException("Assertion must be signed");
            }

            final Signature sig2 = assertion.getSignature();
            sigValidator.validate(sig2);

            // Assertion must contain an authnstatement
            // with an unexpired session
            if (assertion.getAuthnStatements().isEmpty()) {
                throw new ValidationException("Assertion should contain an AuthnStatement");
            }
            for (AuthnStatement as : assertion.getAuthnStatements()) {
                if (as.getSessionNotOnOrAfter() == null) {
                    LOG.error("SessionNotOnOrAfter is null");
                    continue;
                }
                final DateTime exp = as.getSessionNotOnOrAfter().plusSeconds(slack);
                if (exp != null
                        && (now.isEqual(exp) || now.isAfter(exp))) {
                    throw new ValidationException("AuthnStatement has expired");
                }
            }

            if (assertion.getConditions() == null) {
                throw new ValidationException("Assertion should contain conditions");
            }

            // Assertion IssueInstant must be within a day
            final DateTime instant = assertion.getIssueInstant();
            if (instant != null) {
                if (instant.isBefore(now.minusDays(1).minusSeconds(slack))) {
                    throw new ValidationException("Response IssueInstant is in the past");
                }

                if (instant.isAfter(now.plusDays(1).plusSeconds(slack))) {
                    throw new ValidationException("Response IssueInstant is in the future");
                }
            }

            // Conditions must be met by current time
            final Conditions conditions = assertion.getConditions();
            DateTime notBefore = conditions.getNotBefore();
            DateTime notOnOrAfter = conditions.getNotOnOrAfter();

            if (notBefore == null) {
                notBefore = now;
            }

            if (notBefore == null || notOnOrAfter == null) {
                throw new ValidationException("Assertion conditions must have limits");
            }

            notBefore = notBefore.minusSeconds(slack);
            notOnOrAfter = notOnOrAfter.plusSeconds(slack);

            if (now.isBefore(notBefore)) {
                throw new ValidationException("Assertion conditions is in the future");
            }

            if (now.isEqual(notOnOrAfter) || now.isAfter(notOnOrAfter)) {
                throw new ValidationException("Assertion conditions is in the past");
            }

            // If subjectConfirmationData is included, it must
            // have a recipient that matches ACS, with a valid
            // NotOnOrAfter
            final Subject subject = assertion.getSubject();
            if (subject != null && !subject.getSubjectConfirmations().isEmpty()) {
                boolean foundRecipient = false;
                for (SubjectConfirmation sc : subject.getSubjectConfirmations()) {
                    if (sc.getSubjectConfirmationData() == null) {
                        continue;
                    }

                    final SubjectConfirmationData scd = sc.getSubjectConfirmationData();
                    if (scd.getNotOnOrAfter() != null) {
                        final DateTime chkdate = scd.getNotOnOrAfter().plusSeconds(slack);
                        if (now.isEqual(chkdate) || now.isAfter(chkdate)) {
                            throw new ValidationException("SubjectConfirmationData is in the past");
                        }
                    }

                    if (config.getSPConfig().getAcs().equals(scd.getRecipient())) {
                        foundRecipient = true;
                    }
                }

                if (!foundRecipient) {
                    throw new ValidationException("No SubjectConfirmationData found for ACS");
                }
            }

            // audience must include intended SP issuer
            if (conditions.getAudienceRestrictions().isEmpty()) {
                throw new ValidationException("Assertion conditions must have audience restrictions");
            }

            // only one audience restriction supported: we can only
            // check against the single SP.
            if (conditions.getAudienceRestrictions().size() > 1) {
                throw new ValidationException("Assertion contains multiple audience restrictions");
            }

            final AudienceRestriction ar = conditions.getAudienceRestrictions().get(0);

            // at least one of the audiences must match our SP
            boolean foundSP = false;
            for (Audience a : ar.getAudiences()) {
                if (config.getSPConfig().getEntityId().equals(a.getAudienceURI())) {
                    foundSP = true;
                }
            }
            if (!foundSP) {
                throw new ValidationException("Assertion audience does not include issuer");
            }
        }
    }

    private Signature getSignature() {
        try {
            final char[] jksPassword = config.getKeystorePassword();
            final String alias = config.getCertificateAlias();
            final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            try (final FileInputStream fileInputStream = new FileInputStream(config.getKeystore())) {
                keyStore.load(fileInputStream, jksPassword);
            }
            final KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, new KeyStore.PasswordProtection(jksPassword));
            final PrivateKey privateKey = privateKeyEntry.getPrivateKey();
            final X509Certificate certificate = (X509Certificate) privateKeyEntry.getCertificate();

            final BasicX509Credential credential = new BasicX509Credential();
            credential.setEntityCertificate(certificate);
            credential.setPrivateKey(privateKey);

            final Signature signature = (Signature) org.opensaml.xml.Configuration.getBuilderFactory()
                    .getBuilder(org.opensaml.xml.signature.Signature.DEFAULT_ELEMENT_NAME)
                    .buildObject(org.opensaml.xml.signature.Signature.DEFAULT_ELEMENT_NAME);
            signature.setSigningCredential(credential);
            final SecurityConfiguration securityConfiguration = Configuration.getGlobalSecurityConfiguration();
            final String keyInfoGeneratorProfile = null;
            SecurityHelper.prepareSignatureParams(signature, credential, securityConfiguration, keyInfoGeneratorProfile);
            return signature;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | SecurityException ex) {
            Logger.getLogger(SAMLClient.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }

    public AuthnRequest createAuthnRequest(final String requestId) {
        final AuthnRequest request = new AuthnRequestBuilder().buildObject();
        request.setAssertionConsumerServiceURL(config.getSPConfig().getAcs());
        request.setDestination(config.getIdPConfig().getLoginUrl());
        request.setIssueInstant(new DateTime());
        request.setID(requestId);

        final NameIDPolicy nameIDPolicy = new NameIDPolicyBuilder().buildObject();
        nameIDPolicy.setFormat(NameIDType.UNSPECIFIED);
        request.setNameIDPolicy(nameIDPolicy);

        final Issuer issuer = new IssuerBuilder().buildObject();
        issuer.setValue(config.getSPConfig().getEntityId());
        request.setIssuer(issuer);
        request.setSignature(getSignature());
        return request;
    }

    private String _createAuthnRequest(final String requestId) throws SAMLException {
        final AuthnRequest request = createAuthnRequest(requestId);

        try {
            // samlobject to xml dom object
            final Element elem = Configuration.getMarshallerFactory()
                    .getMarshaller(request)
                    .marshall(request);

            // and to a string...
            final Document document = elem.getOwnerDocument();
            final DOMImplementationLS domImplLS = (DOMImplementationLS) document
                    .getImplementation();
            final LSSerializer serializer = domImplLS.createLSSerializer();
            serializer.getDomConfig().setParameter("xml-declaration", false);
            return serializer.writeToString(elem);
        } catch (MarshallingException e) {
            throw new SAMLException(e);
        }
    }

    private byte[] deflate(final byte[] input) throws IOException {
        // deflate and base-64 encode it
        final Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        deflater.setInput(input);
        deflater.finish();

        byte[] tmp = new byte[8192];
        int count;

        final ByteArrayOutputStream bos = new ByteArrayOutputStream();
        while (!deflater.finished()) {
            count = deflater.deflate(tmp);
            bos.write(tmp, 0, count);
        }
        bos.close();
        deflater.end();

        return bos.toByteArray();
    }

    /**
     * Create a new AuthnRequest suitable for sending to an HTTPRedirect binding
     * endpoint on the IdP. The SPConfig will be used to fill in the ACS and
     * issuer, and the IdP will be used to set the destination.
     *
     * @param requestId random generated RequestId
     * @return a deflated, base64-encoded AuthnRequest
     * @throws org.adeptnet.atlassian.saml.SAMLException
     */
    public String generateAuthnRequest(final String requestId) throws SAMLException {
        final String request = _createAuthnRequest(requestId);

        try {
            final byte[] compressed = deflate(request.getBytes("UTF-8"));
            return DatatypeConverter.printBase64Binary(compressed);
        } catch (UnsupportedEncodingException e) {
            throw new SAMLException("Apparently your platform lacks UTF-8.  That's too bad.", e);
        } catch (IOException e) {
            throw new SAMLException("Unable to compress the AuthnRequest", e);
        }
    }

    private byte[] inflate(final byte[] content) throws java.io.IOException {
        try (final java.io.InputStream is = new java.io.ByteArrayInputStream(content);
                final java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream(content.length * 2);
                final InflaterInputStream iis = new InflaterInputStream(is, new Inflater(true))) {
            final byte[] buffer = new byte[4096];
            int n = 0;
            while (-1 != (n = iis.read(buffer))) {
                baos.write(buffer, 0, n);
            }
            baos.flush();
            return baos.toByteArray();
        }
    }

    private AttributeSet getAttributeSet(final Response response) throws SAMLException {
        // we only look at first assertion
        if (response.getAssertions().size() != 1) {
            throw new SAMLException("Response should have a single assertion.");
        }
        final Assertion assertion = response.getAssertions().get(0);

        final Subject subject = assertion.getSubject();
        if (subject == null) {
            throw new SAMLException("No subject contained in the assertion.");
        }
        if (subject.getNameID() == null) {
            throw new SAMLException("No NameID found in the subject.");
        }

        final String nameId = subject.getNameID().getValue();

        final HashMap<String, List<String>> attributes = new HashMap<>();

        for (AttributeStatement atbs : assertion.getAttributeStatements()) {
            for (Attribute atb : atbs.getAttributes()) {
                final String name = atb.getName();
                final List<String> values = new ArrayList<>();
                for (XMLObject obj : atb.getAttributeValues()) {
                    values.add(obj.getDOM().getTextContent());
                }
                attributes.put(name, values);
            }
        }
        return new AttributeSet(nameId, attributes);
    }

    /**
     * Check an authnResponse and return the subject if validation succeeds. The
     * NameID from the subject in the first valid assertion is returned along
     * with the attributes.
     *
     * @param _authnResponse a base64-encoded AuthnResponse from the SP
     * @throws SAMLException if validation failed.
     * @return the authenticated subject/attributes as an AttributeSet
     */
    public AttributeSet validateResponsePOST(final String _authnResponse) throws SAMLException {
        final byte[] decoded = DatatypeConverter.parseBase64Binary(_authnResponse);
        final String authnResponse;
        try {
            authnResponse = new String(decoded, "UTF-8");
            if (LOG.isTraceEnabled()) {
                LOG.trace(authnResponse);
            }
        } catch (UnsupportedEncodingException e) {
            throw new SAMLException("UTF-8 is missing, oh well.", e);
        }

        final Response response = parseResponse(authnResponse);

        try {
            validatePOST(response);
        } catch (ValidationException e) {
            throw new SAMLException(e);
        }

        return getAttributeSet(response);
    }

    private DocumentBuilder createDocumentBuilder(boolean validating, boolean disAllowDocTypeDeclarations) throws ParserConfigurationException {
        final DocumentBuilderFactory dfactory = DocumentBuilderFactory.newInstance();
        dfactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, Boolean.TRUE);
        if (disAllowDocTypeDeclarations) {
            dfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        }
        dfactory.setValidating(validating);
        dfactory.setNamespaceAware(true);

        return dfactory.newDocumentBuilder();
    }

    private Element[] selectNodes(final Node _sibling, final String uri, final String nodeName) {
        final List<Element> list = new ArrayList<>();
        Node sibling = _sibling;
        while (sibling != null) {
            if (sibling.getNamespaceURI() != null && sibling.getNamespaceURI().equals(uri)
                    && sibling.getLocalName().equals(nodeName)) {
                list.add((Element) sibling);
            }
            sibling = sibling.getNextSibling();
        }
        return list.toArray(new Element[list.size()]);
    }

    private void initMap() {
        if (!map.isEmpty()) {
            return;
        }
        final InputStream is = org.apache.xml.security.Init.class.getResourceAsStream("resource/config.xml");
        if (is == null) {
            LOG.error("cannot read resource/config.xml");
            return;
        }
        try {
            /* read library configuration file */
            final DocumentBuilder db = createDocumentBuilder(false, true);
            final Document doc = db.parse(is);
            Node node = doc.getFirstChild();
            for (; node != null; node = node.getNextSibling()) {
                if ("Configuration".equals(node.getLocalName())) {
                    break;
                }
            }
            if (node == null) {
                LOG.error("Error in reading configuration file - Configuration element not found");
                return;
            }
            for (Node el = node.getFirstChild(); el != null; el = el.getNextSibling()) {
                if (Node.ELEMENT_NODE != el.getNodeType()) {
                    continue;
                }
                if (!"JCEAlgorithmMappings".equals(el.getLocalName())) {
                    continue;
                }
                final Node algorithmsNode = ((Element) el).getElementsByTagName("Algorithms").item(0);
                if (algorithmsNode == null) {
                    continue;
                }

                final Element[] algorithms = selectNodes(algorithmsNode.getFirstChild(), Init.CONF_NS, "Algorithm");
                for (final Element element : algorithms) {
                    final String algoClass = element.getAttributeNS(null, "AlgorithmClass");
                    if (!"Signature".equals(algoClass)) {
                        continue;
                    }
                    final String uri = element.getAttributeNS(null, "URI");
                    final String name = element.getAttributeNS(null, "JCEName");
                    map.put(name, uri);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(String.format("Mapping %s - %s", name, uri));
                    }
                }
            }
        } catch (ParserConfigurationException | SAXException | IOException | DOMException ex) {
            LOG.error(ex.getMessage(), ex);
        }
    }

    private String getAlgorithmURIFromID(final String algo) {
        initMap();

        if (map.containsKey(algo)) {
            return map.get(algo);
        }

        return algo;
    }

    private String getRawQueryStringParameter(final String queryString, final String paramName) {
        if (queryString == null) {
            return null;
        }

        final String paramPrefix = paramName + "=";
        int start = queryString.indexOf(paramPrefix);
        if (start == -1) {
            return null;
        }
        start += paramPrefix.length();

        final int end = queryString.indexOf('&', start);
        if (end == -1) {
            return queryString.substring(start);
        } else {
            return queryString.substring(start, end);
        }
    }

    public AttributeSet validateResponseGET(final String queryString) throws SAMLException {
        final String samlTicket = getRawQueryStringParameter(queryString, Common.SAML_RESPONSE);
        if (samlTicket == null) {
            throw new SAMLException(String.format("%s cannot be null", Common.SAML_RESPONSE));
        }
        final String samlSig = getRawQueryStringParameter(queryString, Common.SAML_SIGALG);
        if (samlSig == null) {
            throw new SAMLException(String.format("%s cannot be null", Common.SAML_SIGALG));
        }
        final String samlSigature = getRawQueryStringParameter(queryString, Common.SAML_SIGNATURE);
        if (samlSigature == null) {
            throw new SAMLException(String.format("%s cannot be null", Common.SAML_SIGNATURE));
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("%s: %s", Common.SAML_RESPONSE, samlTicket));
            LOG.debug(String.format("%s: %s", Common.SAML_SIGALG, samlSig));
            LOG.debug(String.format("%s: %s", Common.SAML_SIGNATURE, samlSigature));
        }
        try {

            final StringBuilder sb = new StringBuilder();
            sb.append(String.format("%s=%s&", Common.SAML_RESPONSE, samlTicket));
            final String samlRelayState = getRawQueryStringParameter(queryString, Common.SAML_RELAYSTATE);
            if (samlRelayState != null) {
                sb.append(String.format("%s=%s&", Common.SAML_RELAYSTATE, samlRelayState));
            }
            sb.append(String.format("%s=%s", Common.SAML_SIGALG, samlSig));

            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("%s: %s", "verification", sb.toString()));
            }

            if (!SigningUtil.verifyWithURI(cred, getAlgorithmURIFromID(samlSig), DatatypeConverter.parseBase64Binary(HTTPTransportUtils.urlDecode(samlSigature)), sb.toString().getBytes("UTF-8"))) {
                throw new SAMLException("!SigningUtil.verifyWithURI");
            }
        } catch (UnsupportedEncodingException | SecurityException ex) {
            throw new SAMLException(ex);
        }

        final byte[] decoded;
        try {
            decoded = inflate(DatatypeConverter.parseBase64Binary(HTTPTransportUtils.urlDecode(samlTicket)));
        } catch (IOException ex) {
            throw new SAMLException(ex);
        }

        final String authnResponse;
        try {
            authnResponse = new String(decoded, "UTF-8");
            if (LOG.isTraceEnabled()) {
                LOG.trace(authnResponse);
            }
        } catch (UnsupportedEncodingException e) {
            throw new SAMLException("UTF-8 is missing, oh well.", e);
        }

        final Response response = parseResponse(authnResponse);

        try {
            validate(response);
        } catch (ValidationException e) {
            throw new SAMLException(e);
        }
        return getAttributeSet(response);
    }

}
