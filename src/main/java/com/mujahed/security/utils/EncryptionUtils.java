package com.mujahed.security.utils;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import javax.xml.namespace.QName;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.InboundXMLSec;
import org.apache.xml.security.stax.ext.OutboundXMLSec;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.securityToken.SecurityTokenConstants;
import org.apache.xml.security.test.stax.utils.StAX2DOM;
import org.apache.xml.security.test.stax.utils.XmlReaderToWriter;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;

import com.ctc.wstx.api.WstxInputProperties;
import com.sun.org.apache.xml.internal.security.Init;

public class EncryptionUtils {

	static {
		Init.init();
	}

	private EncryptionUtils() {
		// complete
	}

	/**
	 * Encrypt the document using the StAX API of Apache Santuario - XML
	 * Security for Java. If wrappingkey is supplied, this is used to encrypt
	 * the encryptingkey + place it in an encryptedkey structure.
	 * 
	 * @param inputStream
	 * @param namesToEncrypt
	 * @param algorithm
	 * @param encryptionKey
	 * @param keyTransportAlgorithm
	 * @param wrappingKey
	 * @param content
	 * @return
	 * @throws XMLSecurityException
	 * @throws XMLStreamException
	 */
	public static ByteArrayOutputStream encryptUsingStAX(
			InputStream inputStream, List<QName> namesToEncrypt,
			String algorithm, Key encryptionKey, String keyTransportAlgorithm,
			PublicKey wrappingKey, boolean content)
			throws XMLSecurityException, XMLStreamException {

		XMLSecurityProperties properties = setupConfigurationProperties(
				algorithm, encryptionKey, keyTransportAlgorithm, wrappingKey);

		SecurePart.Modifier modifier = SecurePart.Modifier.Content;
		if (!content) {
			modifier = SecurePart.Modifier.Element;
		}

		for (QName nameToEncrypt : namesToEncrypt) {
			SecurePart securePart = new SecurePart(nameToEncrypt, modifier);
			properties.addEncryptionPart(securePart);
		}

		OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(
				baos, "UTF-8");

		XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
		XMLStreamReader xmlStreamReader = xmlInputFactory
				.createXMLStreamReader(inputStream);

		XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
		xmlStreamWriter.close();
		return baos;

	}

	public static ByteArrayOutputStream decryptUsingStAXV2(
			InputStream inputStream, Key privateKey)
			throws XMLSecurityException, XMLStreamException {
		XMLSecurityProperties properties = new XMLSecurityProperties();
		List<XMLSecurityConstants.Action> actions = new ArrayList<XMLSecurityConstants.Action>();
		actions.add(XMLSecurityConstants.ENCRYPT);
		properties.setActions(actions);
		properties.setDecryptionKey(privateKey);

		InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
		XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
		xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
		xmlInputFactory.setProperty(
				XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
		xmlInputFactory.setProperty(XMLInputFactory.IS_COALESCING, false);
		xmlInputFactory.setProperty(WstxInputProperties.P_MIN_TEXT_SEGMENT,
				new Integer(8192));
		final XMLStreamReader xmlStreamReader = xmlInputFactory
				.createXMLStreamReader(inputStream);
		XMLStreamReader securityStreamReader = inboundXMLSec.processInMessage(
				xmlStreamReader, null, null);
		XMLOutputFactory factory = XMLOutputFactory.newInstance();
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		XMLStreamWriter writer = factory.createXMLStreamWriter(baos);
		XmlReaderToWriter.writeAll(securityStreamReader, writer);

		writer.flush();
		writer.close();
		return baos;
	}

	public static Document decryptUsingStAX(InputStream inputStream,
			Key privateKey) throws XMLSecurityException, XMLStreamException,
			ParserConfigurationException {
		XMLSecurityProperties properties = new XMLSecurityProperties();
		List<XMLSecurityConstants.Action> actions = new ArrayList<XMLSecurityConstants.Action>();
		actions.add(XMLSecurityConstants.ENCRYPT);
		properties.setActions(actions);
		properties.setDecryptionKey(privateKey);

		InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);

		XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
		final XMLStreamReader xmlStreamReader = xmlInputFactory
				.createXMLStreamReader(inputStream);

		XMLStreamReader securityStreamReader = inboundXMLSec.processInMessage(
				xmlStreamReader, null, null);
		return StAX2DOM.readDoc(XMLUtils.createDocumentBuilder(false),
				securityStreamReader);
	}

	static XMLSecurityProperties setupConfigurationProperties(String algorithm,
			Key encryptionKey, String keyTransportAlgorithm,
			PublicKey wrappingKey) {
		XMLSecurityProperties properties = new XMLSecurityProperties();

		List<XMLSecurityConstants.Action> actions = new ArrayList<XMLSecurityConstants.Action>();
		actions.add(XMLSecurityConstants.ENCRYPT);
		properties.setActions(actions);

		properties.setEncryptionSymAlgorithm(algorithm);
		properties.setEncryptionKey(encryptionKey);
		properties.setEncryptionKeyTransportAlgorithm(keyTransportAlgorithm);
		properties.setEncryptionTransportKey(wrappingKey);
		properties
				.setEncryptionKeyIdentifier(SecurityTokenConstants.KeyIdentifier_X509KeyIdentifier);
		return properties;
	}
}
