package com.mujahed.security.utils;

import java.util.ArrayList;
import java.util.List;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

//import org.apache.log4j.Logger;

public class QNameList {

	//private static final Logger LOGGER = Logger.getLogger(QNameList.class);

	private static final String encryptPI = "encrypt-me";

	private QNameList() {
	}

	public static List<QName> getQNames(XMLStreamReader reader)
			throws XMLStreamException {
		List<QName> qnames = new ArrayList<QName>();

		while (reader.hasNext()) {
			int next = reader.next();

			if (next == XMLStreamReader.PROCESSING_INSTRUCTION
					&& reader.getPITarget().equals(encryptPI)) {
				// encrypt the next element
				int eventType = reader.next();
				qnames.add(readCharacters(reader, eventType));
			}
		}

		return qnames;
	}

	private static QName readCharacters(XMLStreamReader reader, int eventType)
			throws XMLStreamException {
		QName qname = null;

		while (reader.hasNext()) {
			switch (eventType) {
			case XMLStreamReader.START_ELEMENT:
				qname = reader.getName();
				return qname;
			case XMLStreamReader.END_ELEMENT:
				qname = reader.getName();
				return qname;
			default:
				throw new XMLStreamException("UNKNOWN_EVENT_TYPE, "
						+ reader.getEventType());
			}
		}
		throw new XMLStreamException("Premature end of file");
	}
}
