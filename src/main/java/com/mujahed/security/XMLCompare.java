package com.mujahed.security;

import java.io.IOException;

import org.custommonkey.xmlunit.XMLTestCase;

public class XMLCompare extends XMLTestCase {

	public void test(String contents, String decryptedContents)
			throws IOException {
		try {
			assertXMLEqual("original and decrypted XML not equal: ", contents,
					decryptedContents);
		} catch (org.xml.sax.SAXException e) {
			e.getMessage();
		}

	}

}
