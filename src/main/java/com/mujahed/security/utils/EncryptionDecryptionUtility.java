package com.mujahed.security.utils;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.util.List;

import javax.xml.namespace.QName;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.log4j.Logger;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.w3c.dom.Document;

public class EncryptionDecryptionUtility {

	private EncryptionConfigurationBean encBean;
	private static List<QName> namesToEncrypt;

	private static final Logger LOGGER = Logger
			.getLogger(EncryptionDecryptionUtility.class);

	public EncryptionDecryptionUtility() {
	}

	public EncryptionConfigurationBean getEncBean() {
		return encBean;
	}

	public void setEncBean(EncryptionConfigurationBean encBean) {
		this.encBean = encBean;
	}

	public String encryptWithStax(String data) throws IOException,
			XMLSecurityException, XMLStreamException {
		InputStream sourceDocument = new ByteArrayInputStream(
				data.getBytes("UTF8"));
		if (LOGGER.isInfoEnabled()) {
			LOGGER.info("sourceDocument is available :"
					+ sourceDocument.available());
		}

		// encypt with stax
		ByteArrayOutputStream baos = EncryptionUtils.encryptUsingStAX(
				sourceDocument, findNamesToEncrypt(data), encBean
						.getAlgorithmIdentifier(), encBean.getSecretKey(),
				encBean.getKeyTransportAlgorithm(), encBean.getCert()
						.getPublicKey(), encBean.isDataLevelEncryption());
		return baos.toString("UTF-8");
	}

	private static List<QName> findNamesToEncrypt(String data)
			throws UnsupportedEncodingException, XMLStreamException {
		InputStream copySourceDocument = new ByteArrayInputStream(
				data.getBytes("UTF8"));
		XMLInputFactory inputFactory = XMLInputFactory.newInstance();
		namesToEncrypt = QNameList.getQNames(inputFactory
				.createXMLStreamReader(copySourceDocument));
		return namesToEncrypt;
	}

	public String decryptWithStax(String data) throws IOException,
			XMLSecurityException, XMLStreamException,
			ParserConfigurationException, TransformerException {
		InputStream sourceDocument = new ByteArrayInputStream(
				data.getBytes("UTF8"));
		ByteArrayOutputStream baos = (ByteArrayOutputStream) copyStream(
				sourceDocument, new ByteArrayOutputStream());
		Document doc = EncryptionUtils.decryptUsingStAX(
				new ByteArrayInputStream(baos.toByteArray()),
				encBean.getPrivateKey());
		String resultString = getStringFromDocument(doc);
		return resultString;
	}

	private String getStringFromDocument(Document doc)
			throws TransformerException {
		DOMSource domSource = new DOMSource(doc);
		StringWriter writer = new StringWriter();
		StreamResult result = new StreamResult(writer);
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer transformer = tf.newTransformer();
		transformer.transform(domSource, result);
		return writer.toString();
	}

	private static ByteArrayOutputStream copyStream(InputStream sourceDocument,
			ByteArrayOutputStream byteArrayOutputStream) throws IOException {
		byte[] buffer = new byte[1024];
		int bytesRead;

		while ((bytesRead = sourceDocument.read(buffer)) != -1) {
			byteArrayOutputStream.write(buffer, 0, bytesRead);
		}
		return byteArrayOutputStream;
	}
}
