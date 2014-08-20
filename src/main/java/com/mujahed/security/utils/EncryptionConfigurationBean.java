package com.mujahed.security.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.log4j.Logger;

public class EncryptionConfigurationBean {

	private static final Logger LOGGER = Logger
			.getLogger(EncryptionConfigurationBean.class);

	private static final String keyStoreInstanceType = "JKS";

	private String alias;
	private String jksFile;
	private String password;
	private KeyStore keyStore;
	private X509Certificate cert;
	private SecretKey secretKey;
	private String algorithm;
	private boolean dataLevelEncryption;
	private String algorithmIdentifier;
	private String keyTransportAlgorithm;

	// for decryption
	private Key privateKey;
	private String privatePassword;

	public String getAlias() {
		return alias;
	}

	public void setAlias(String alias) {
		this.alias = alias;
	}

	public String getJksFile() {
		return jksFile;
	}

	public void setJksFile(String jksFile) {
		this.jksFile = jksFile;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public KeyStore getKeyStore() {
		return keyStore;
	}

	public void setKeyStore(KeyStore keyStore) throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException {
		FileInputStream jksStream = null;
		KeyStore defaultKeyStore = null;

		if (keyStore == null) {
			defaultKeyStore = KeyStore.getInstance(keyStoreInstanceType);
			try {
				jksStream = new FileInputStream(new File(getJksFile()));
				defaultKeyStore.load(jksStream, getPassword().toCharArray());
				this.keyStore = defaultKeyStore;
			} finally {
				if (jksStream != null) {
					jksStream.close();
				}
			}
		} else {
			this.keyStore = keyStore;
		}
	}

	public X509Certificate getCert() {
		return cert;
	}

	public void setCert(X509Certificate cert) throws KeyStoreException {
		X509Certificate defaultCert = null;
		if (cert == null) {
			if (LOGGER.isInfoEnabled()) {
				LOGGER.info("cert is null trying to set defaul ..");
			}

			if (!keyStore.containsAlias(this.alias)) {
				throw new RuntimeException("Alias for key not found");
			}
			defaultCert = (X509Certificate) keyStore.getCertificate(this.alias);
			if (LOGGER.isInfoEnabled()) {
				LOGGER.info("defaultCert " + defaultCert);
			}
			this.cert = defaultCert;
		} else {
			this.cert = cert;
		}
	}

	public SecretKey getSecretKey() {
		return secretKey;
	}

	public void setSecretKey(SecretKey secretKey)
			throws NoSuchAlgorithmException {
		SecretKey defaultSecretKey = null;
		if (secretKey == null) {
			KeyGenerator keygen = KeyGenerator.getInstance(this.algorithm);
			keygen.init(128);
			defaultSecretKey = keygen.generateKey();
			this.secretKey = defaultSecretKey;
		} else {
			this.secretKey = secretKey;
		}
	}

	public String getAlgorithm() {
		return algorithm;
	}

	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}

	public boolean isDataLevelEncryption() {
		return dataLevelEncryption;
	}

	public void setDataLevelEncryption(boolean dataLevelEncryption) {
		this.dataLevelEncryption = dataLevelEncryption;
	}

	public String getAlgorithmIdentifier() {
		return algorithmIdentifier;
	}

	public void setAlgorithmIdentifier(String algorithmIdentifier) {
		this.algorithmIdentifier = algorithmIdentifier;
	}

	public String getKeyTransportAlgorithm() {
		return keyTransportAlgorithm;
	}

	public void setKeyTransportAlgorithm(String keyTransportAlgorithm) {
		this.keyTransportAlgorithm = keyTransportAlgorithm;
	}

	public Key getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(Key privateKey) throws UnrecoverableKeyException,
			KeyStoreException, NoSuchAlgorithmException {
		Key defaultPrivateKey = null;

		if (privateKey == null) {
			defaultPrivateKey = getKeyStore().getKey(this.alias,
					this.privatePassword.toCharArray());
			this.privateKey = defaultPrivateKey;
		} else {
			this.privateKey = privateKey;
		}
	}

	public String getPrivatePassword() {
		return privatePassword;
	}

	public void setPrivatePassword(String privatePassword) {
		this.privatePassword = privatePassword;
	}
}
