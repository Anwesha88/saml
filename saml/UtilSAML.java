/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.fm.fmwebcare.util;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.*;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 *
 * @author DPatra
 */
public class UtilSAML {

    public static void readAuthnAssertion(String filename,HttpServletRequest request,HttpServletResponse resp)
            throws Exception {
        String uid="";
        DefaultBootstrap.bootstrap();
        Response response = unmarshalSamlResponse(filename);
        System.out.println(response.getAssertions().size());
        String statusCode = response.getStatus().getStatusCode().getValue();
        System.out.println("statusCode :: " + statusCode);
        System.out.println("getVersion :: " + response.getVersion());
        // response.get


        //System.out.println(sig);
        // SignatureValidator validator = new SignatureValidator();
        //validator.validate(sig);

        for (Assertion assertion : response.getAssertions()) {
            //Signature sig = assertion.getSignature();
            //validate(sig);
            //System.out.println("getSignatureAlgorithm"+sig.getSignatureAlgorithm());
            // System.out.println("value"+sig.getDOM().getNodeName());
            NameID nameID = assertion.getSubject().getNameID();

            System.out.println("Assertion issued by " +
                    assertion.getIssuer().getValue());
            System.out.println("Subject name: " + nameID.getValue());
            System.out.println("  (Format " + nameID.getFormat() + ")");

            System.out.println("Authentication context classes found:");
            for (Statement statement : assertion.getStatements()) {
                System.out.println("Satement");
                if (statement instanceof AuthnStatement) {
                    System.out.println("  " + ((AuthnStatement) statement).getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef());
                } else {
                    // System.out.println (s);
                }
            }
            uid=getValueFromAttributeStatements(assertion, "uid");
            System.out.println(uid);
            System.out.println(getValueFromAttributeStatements(assertion, "mail"));
            System.out.println(getValueFromAttributes(assertion, "locs"));
        }
        request.setAttribute("username", uid);
        request.setAttribute("saml", "00");
        RequestDispatcher rd=request.getRequestDispatcher("login");
        rd.forward(request, resp);
    }

    private  static String getValueFromAttributeStatements(final Assertion assertion, final String name) {
        final List<AttributeStatement> attributeStatements = assertion.getAttributeStatements();
        for (AttributeStatement attributeStatement : attributeStatements) {
            final List<Attribute> attributes = attributeStatement.getAttributes();
            for (Attribute attribute : attributes) {
                if (name.equals(attribute.getName())) {
                    XMLObject xmlObject = attribute.getAttributeValues().get(0);
                    String nodeValue = xmlObject.getDOM().getFirstChild().getNodeValue();
                    return nodeValue;
                }
            }
        }
        return "";
    }

    private static String getValueFromAttributes(final Assertion assertion, final String name) {
        final List<AttributeStatement> attributeStatements = assertion.getAttributeStatements();
        for (AttributeStatement attributeStatement : attributeStatements) {
            final List<Attribute> attributes = attributeStatement.getAttributes();
            for (Attribute attribute : attributes) {
                if (name.equals(attribute.getName())) {
                    String nodeValue = "";
                    XMLObject xmlObject = null;
                    for (int i = 0; i < attribute.getAttributeValues().size(); i++) {
                        xmlObject = attribute.getAttributeValues().get(i);
                        nodeValue += xmlObject.getDOM().getFirstChild().getNodeValue() + ",";

                    }

                    return nodeValue;
                }
            }
        }
        return "";
    }

    private static Response unmarshalSamlResponse(final String samlResponse) throws XMLParserException, UnmarshallingException {
        BasicParserPool ppMgr = new BasicParserPool();
        ppMgr.setNamespaceAware(true);
        Document doc = ppMgr.parse(new ByteArrayInputStream(samlResponse.getBytes()));
        Element responseRoot = doc.getDocumentElement();
        System.out.println(responseRoot.getNodeName());
        UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(responseRoot);
         System.out.println("unmarshaller"+unmarshaller);
        XMLObject responseXmlObj = unmarshaller.unmarshall(responseRoot);
        return (Response) unmarshaller.unmarshall(responseRoot);
    }

    private  static boolean validate(Signature sig, String xml) throws Exception {
        boolean returnValue = false;
        try {

            Response response = unmarshalSamlResponse(xml);

            //Get Public Key
            BasicX509Credential publicCredential = new BasicX509Credential();
            File publicKeyFile = new File("C:/key/saml.cer");

            if (publicKeyFile.exists()) {
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
                InputStream fileStream = new FileInputStream(publicKeyFile);
                X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(fileStream);
                fileStream.close();

                X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(certificate.getPublicKey().getEncoded());
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PublicKey key = keyFactory.generatePublic(publicKeySpec);

                //Validate Public Key against Signature
                if (key != null) {
                    publicCredential.setPublicKey(key);
                    SignatureValidator signatureValidator = new SignatureValidator(publicCredential);
                    signatureValidator.validate(sig);
                }

            }
            returnValue = true;
        } catch (Exception e) {
            throw e; //Throws a 'Signature did not validate against the credential's key' exception
        }
        return returnValue;
    }
}
