package com.mujahed.security;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamException;
import javax.xml.transform.TransformerException;

import org.apache.log4j.Logger;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.util.StopWatch;

import com.mujahed.security.utils.EncryptionDecryptionUtility;

import org.custommonkey.xmlunit.*;

/**
 * Hello world!
 * 
 */
public class App {
	private static final Logger LOGGER = Logger.getLogger(App.class);

	public static void main(String[] args) throws IOException,
			XMLSecurityException, XMLStreamException,
			ParserConfigurationException, TransformerException {
		ClassPathXmlApplicationContext ctx = new ClassPathXmlApplicationContext(
				"spring.xml");
		EncryptionDecryptionUtility util = (EncryptionDecryptionUtility) ctx
				.getBean("encUtil");

		InputStream stream = new FileInputStream(new File(
				"src/main/resources/data-file.xml"));
		BufferedReader reader = new BufferedReader(new InputStreamReader(
				stream, "UTF-8"));
		String contents = null;
		StringBuilder builder = new StringBuilder();
		while (reader.ready()) {
			builder.append(reader.readLine());
		}
		contents = builder.toString();

		String encryptedContents = util.encryptWithStax(contents);

		StopWatch decryptedTimer = new StopWatch();
		decryptedTimer.start();
		String decryptedContents = util.decryptWithStax(encryptedContents);
		decryptedTimer.stop();

		LOGGER.error("decryptionTime: " + decryptedTimer.getTotalTimeSeconds());

		if (LOGGER.isInfoEnabled()) {
			LOGGER.info("encryptedContents: " + encryptedContents);
			LOGGER.info("decryptedContents: " + decryptedContents);
		}

		reader.close();
		ctx.close();

		new XMLCompare().test(contents, decryptedContents);
	}
}
