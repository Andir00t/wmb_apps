package ru.pochtabank.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.KeySelector;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.MimeHeaders;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.TransformerException;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.token.X509Security;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xpath.XPathAPI;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.ibm.broker.javacompute.MbJavaComputeNode;
import com.ibm.broker.plugin.MbElement;
import com.ibm.broker.plugin.MbException;
import com.ibm.broker.plugin.MbMessage;
import com.ibm.broker.plugin.MbMessageAssembly;
import com.ibm.broker.plugin.MbOutputTerminal;
import com.ibm.broker.plugin.MbUserException;
import com.ibm.broker.plugin.MbXMLNS;
import com.ibm.broker.plugin.MbXMLNSC;

public class Pochtabank_adpesia_JavaCompute extends MbJavaComputeNode {

	private final String PASSWORD = (String) getUserDefinedAttribute("KeyStorePass");
	private final String ALIAS = (String) getUserDefinedAttribute("KeyStoreAlias");
	private final String STORETYPE = (String) getUserDefinedAttribute("KeyStoreType");
	private static final String WSSECURITY_SECEXT_URI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private static final String WSSECURITY_UTILITY_URI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
	
	private Provider xmlDSigProvider;
	private KeyStore keyStore;
	private PrivateKey privateKey;
	private X509Certificate cert;

	public void evaluate(MbMessageAssembly inAssembly) throws MbException {

		MbOutputTerminal out = getOutputTerminal("out");
		// MbOutputTerminal error = getOutputTerminal("alternate");
		MbMessage inMessage = inAssembly.getMessage();
		MbMessage outMessage = new MbMessage();
		MbMessageAssembly outAssembly = new MbMessageAssembly(inAssembly,
				outMessage);
		MbMessage locEnv = outAssembly.getLocalEnvironment();

		try {

			MbElement reqMethod = inMessage.getRootElement().getLastChild()
					.getLastChild().getLastChild().getLastChild();
			String reqMethodName = reqMethod.getName();

			if (reqMethodName.equals("Identification")) {
				locEnv.getRootElement()
						.evaluateXPath(
								"?Destination/?SOAP/?Request/?Operation[set-value('identify')]");
			} else if (reqMethodName.equals("Verification")) {
				locEnv.getRootElement()
						.evaluateXPath(
								"?Destination/?SOAP/?Request/?Operation[set-value('verify')]");
			} else if (reqMethodName.equals("IdentificationResult")) {
				locEnv.getRootElement()
						.evaluateXPath(
								"?Destination/?SOAP/?Request/?Operation[set-value('getIdentificationResult')]");
			} else if (reqMethodName.equals("VerificationResult")) {
				locEnv.getRootElement()
						.evaluateXPath(
								"?Destination/?SOAP/?Request/?Operation[set-value('getVerificationResult')]");
			}

			MbElement unsignSOAP = inMessage.getRootElement().getLastChild();
			byte[] bs = unsignSOAP.toBitstream("", "", "", 0, 1208, 0);
			String unsigSOAPValue = new String(bs, "UTF-8");
			SOAPMessage unsigSOAPMsg = MessageFactory.newInstance()
					.createMessage(
							new MimeHeaders(),
							new ByteArrayInputStream(unsigSOAPValue
									.getBytes(Charset.forName("UTF-8"))));

			initCM();
			String signSOAP = signSOAPMessage(unsigSOAPMsg);
			outMessage.getRootElement().createElementAsLastChildFromBitstream(
					signSOAP.getBytes("UTF-8"), MbXMLNSC.PARSER_NAME, null,
					null, null, 0, 1208, 0);

		} catch (MbException e) {
			throw e;
		} catch (RuntimeException e) {
			throw e;
		} catch (Exception e) {
			throw new MbUserException(this, "evaluate()", "", "", e.toString(),
					null);
		}

		out.propagate(outAssembly);

	}

	private void initCM() {

		org.apache.xml.security.Init.init();
		xmlDSigProvider = new ru.CryptoPro.JCPxml.dsig.internal.dom.XMLDSigRI();

		try {

			keyStore = KeyStore.getInstance(STORETYPE);
			keyStore.load(null, null);
			privateKey = (PrivateKey) keyStore.getKey(ALIAS, null); //PASSWORD.toCharArray());
			cert = (X509Certificate) keyStore.getCertificate(ALIAS);

		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		}
	}

	public String signSOAPMessage(SOAPMessage soapMessage) throws SOAPException,
			WSSecurityException, KeyStoreException, CertificateException,
			NoSuchAlgorithmException, IOException, TransformationException,
			InvalidAlgorithmParameterException, MarshalException,
			XMLSignatureException, TransformerException,
			UnrecoverableKeyException {
		prepareMessageForSigning(soapMessage);

		Document doc = soapMessage.getSOAPPart().getEnvelope()
				.getOwnerDocument();

		final Transforms transforms = new Transforms(doc);
		transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM",
				xmlDSigProvider);

		List<Transform> transformList = new ArrayList<Transform>();
		Transform transformC14N = fac.newTransform(
				Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS,
				(XMLStructure) null);
		transformList.add(transformC14N);

		Reference ref = fac.newReference("#body", fac.newDigestMethod(
				"http://www.w3.org/2001/04/xmldsig-more#gostr3411", null),
				transformList, null, null);

		SignedInfo si = fac
				.newSignedInfo(
						fac.newCanonicalizationMethod(
								CanonicalizationMethod.EXCLUSIVE,
								(C14NMethodParameterSpec) null),
						fac.newSignatureMethod(
								"http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411",
								null), Collections.singletonList(ref));

		KeyInfoFactory kif = fac.getKeyInfoFactory();
		X509Data x509d = kif.newX509Data(Collections.singletonList(cert));
		KeyInfo ki = kif.newKeyInfo(Collections.singletonList(x509d));

		Element token = (Element) soapMessage.getSOAPHeader()
				.getChildElements().next();
		javax.xml.crypto.dsig.XMLSignature sig = fac.newXMLSignature(si, ki);
		DOMSignContext signContext = new DOMSignContext(privateKey, token);
		sig.sign(signContext);

		Element sigE = (Element) XPathAPI.selectSingleNode(
				signContext.getParent(), "//ds:Signature");
		Node keyE = XPathAPI.selectSingleNode(sigE, "//ds:KeyInfo", sigE);
		token.getFirstChild().setTextContent(
				XPathAPI.selectSingleNode(keyE, "//ds:X509Certificate", keyE)
						.getFirstChild().getNodeValue());
		keyE.removeChild(XPathAPI.selectSingleNode(keyE, "//ds:X509Data", keyE));
		NodeList chl = keyE.getChildNodes();

		for (int i = 0; i < chl.getLength(); i++) {
			keyE.removeChild(chl.item(i));
		}

		Node str = keyE
				.appendChild(doc
						.createElementNS(
								"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
								"wsse:SecurityTokenReference"));
		Element strRef = (Element) str
				.appendChild(doc
						.createElementNS(
								"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
								"wsse:Reference"));
		strRef.setAttribute(
				"ValueType",
				"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
		strRef.setAttribute("URI", "#CertId");
		token.appendChild(sigE);

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		soapMessage.writeTo(out);
		String strMsg = new String(out.toByteArray(), "utf-8");

		return strMsg;

	}

	public void signElementByTag(SOAPMessage soapMessage, String tag)
			throws Exception {
		NodeList tagNodeList = soapMessage.getSOAPPart().getElementsByTagName(
				tag);
		Document newXMLDocument = DocumentBuilderFactory.newInstance()
				.newDocumentBuilder().newDocument();
		Node copyNode = newXMLDocument.importNode(tagNodeList.item(0), true);
		newXMLDocument.appendChild(copyNode);

		NodeList newNodeList = newXMLDocument.getElementsByTagName(tag);
		Element signedNode = (Element) newNodeList.item(0);

		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM",
				xmlDSigProvider);

		List<Transform> transformList = new ArrayList<Transform>();

		Transform transform = fac.newTransform(Transform.ENVELOPED,
				(XMLStructure) null);
		Transform transformC14N = fac.newTransform(
				Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS,
				(XMLStructure) null);
		transformList.add(transform);
		transformList.add(transformC14N);

		Reference ref = fac.newReference("", fac.newDigestMethod(
				"http://www.w3.org/2001/04/xmldsig-more#gostr3411", null),
				transformList, null, null);

		SignedInfo si = fac
				.newSignedInfo(
						fac.newCanonicalizationMethod(
								CanonicalizationMethod.EXCLUSIVE,
								(C14NMethodParameterSpec) null),
						fac.newSignatureMethod(
								"http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411",
								null), Collections.singletonList(ref));

		KeyInfoFactory kif = fac.getKeyInfoFactory();
		X509Data x509d = kif.newX509Data(Collections.singletonList(cert));
		KeyInfo ki = kif.newKeyInfo(Collections.singletonList(x509d));

		javax.xml.crypto.dsig.XMLSignature sig = fac.newXMLSignature(si, ki);

		DOMSignContext signContext = new DOMSignContext(privateKey, signedNode);
		signContext.putNamespacePrefix(
				javax.xml.crypto.dsig.XMLSignature.XMLNS, "ds");
		sig.sign(signContext);

		Document doc = soapMessage.getSOAPPart().getEnvelope()
				.getOwnerDocument();
		Node signedTag = newXMLDocument.getFirstChild();
		Node oldNode = tagNodeList.item(0);
		Node parentNode = oldNode.getParentNode();
		parentNode.removeChild(oldNode);
		Node newNode = doc.importNode(signedTag, true);
		parentNode.appendChild(newNode);
	}

	private void prepareMessageForSigning(SOAPMessage soapMessage)
			throws SOAPException, WSSecurityException {
		soapMessage.getSOAPPart().getEnvelope()
				.addNamespaceDeclaration("wsse", WSSECURITY_SECEXT_URI);
		soapMessage.getSOAPPart().getEnvelope()
				.addNamespaceDeclaration("wsu", WSSECURITY_UTILITY_URI);

		soapMessage
				.getSOAPPart()
				.getEnvelope()
				.addNamespaceDeclaration("ds",
						"http://www.w3.org/2000/09/xmldsig#");
		soapMessage.getSOAPBody().setAttributeNS(WSSECURITY_UTILITY_URI,
				"wsu:Id", "body");

		WSSecHeader header = new WSSecHeader();
		header.setActor("http://smev.gosuslugi.ru/actors/smev");
		header.setMustUnderstand(false);

		Element sec = header.insertSecurityHeader(soapMessage.getSOAPPart());
		Document doc = soapMessage.getSOAPPart().getEnvelope()
				.getOwnerDocument();

		Element token = (Element) sec.appendChild(doc.createElementNS(
				WSSECURITY_SECEXT_URI, "wsse:BinarySecurityToken"));
		token.setAttribute(
				"EncodingType",
				"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
		token.setAttribute(
				"ValueType",
				"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
		token.setAttribute("wsu:Id", "CertId");
		header.getSecurityHeader().appendChild(token);
	}

	public boolean verifySecuredMessage(SOAPMessage message) throws Exception {
		Document doc = message.getSOAPPart().getEnvelope().getOwnerDocument();
		final Element wssecontext = doc.createElementNS(null,
				"namespaceContext");
		wssecontext
				.setAttributeNS(
						"http://www.w3.org/2000/xmlns/",
						"xmlns:" + "wsse".trim(),
						"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
		NodeList secnodeList = XPathAPI.selectNodeList(
				doc.getDocumentElement(), "//wsse:Security");

		Element r = null;
		Element el;
		if (secnodeList != null && secnodeList.getLength() > 0) {
			String actorAttr;
			for (int i = 0; i < secnodeList.getLength(); i++) {
				el = (Element) secnodeList.item(i);
				actorAttr = el.getAttributeNS(
						"http://schemas.xmlsoap.org/soap/envelope/", "actor");
				if (actorAttr != null
						&& actorAttr
								.equals("http://smev.gosuslugi.ru/actors/smev")) {
					r = (Element) XPathAPI.selectSingleNode(el,
							"//wsse:BinarySecurityToken[1]", wssecontext);
					break;
				}
			}
		}
		if (r == null)
			return false;

		final X509Security x509 = new X509Security(r);
		final X509Certificate cert = (X509Certificate) CertificateFactory
				.getInstance("X.509").generateCertificate(
						new ByteArrayInputStream(x509.getToken()));

		if (cert == null) {
			throw new Exception("Cannot find certificate to verify signature");
		}

		NodeList nl = doc.getElementsByTagNameNS(
				"http://www.w3.org/2000/09/xmldsig#", "Signature");
		if (nl.getLength() == 0) {
			throw new Exception("Cannot find Signature element");
		}

		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM",
				xmlDSigProvider);
		DOMValidateContext valContext = new DOMValidateContext(
				KeySelector.singletonKeySelector(cert.getPublicKey()),
				nl.item(0));
		javax.xml.crypto.dsig.XMLSignature signature = fac
				.unmarshalXMLSignature(valContext);

		return signature.validate(valContext);
	}

}
