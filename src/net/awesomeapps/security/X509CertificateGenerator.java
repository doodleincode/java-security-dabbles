package net.awesomeapps.security;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

/**
 * Generates a self-signed certificate and associated private key.
 * 
 * !!! ONLY SUPPORTED ON JAVA 1.8 AS IT USES THE NON-PUBLIC sun.security.* package !!!
 *
 */
public class X509CertificateGenerator {

	private String commonName;
	private String orgUnitName;
	private String orgName;
	private String city;
	private String state;
	private String country;
	
	// Default the cert will be validate for 365 days
	private int validity = 365;
	
	private CertAndKeyGen certKeyGen;
	private int keysize;
	private PrivateKey privateKey;
	private X509Certificate certificate;
	
	protected X509CertificateGenerator(String algo, String signatureAlgo) throws NoSuchAlgorithmException {
		certKeyGen = new CertAndKeyGen(algo, signatureAlgo);
	}
	
	/**
	 * Get an instance of {@link X509CertificateGenerator} with the given keysize and signature algorithm.
	 *  
	 * @param keysize
	 * 				Can be one of {@link RSA#KEYSIZE_2048} or {@link RSA#KEYSIZE_4096}
	 * @param signatureAlgo
	 * 				Can be one of {@link RSA#SHA1_RSA} or {@link RSA#SHA256_RSA}
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static X509CertificateGenerator getInstance(int keysize, String signatureAlgo) throws NoSuchAlgorithmException {
		X509CertificateGenerator generator = new X509CertificateGenerator(RSA.KEY_ALGO, signatureAlgo);
		generator.setKeysize(keysize);
		
		return generator;
	}
	
	/**
	 * Generate the self-signed cert and associated private key.
	 * 
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	public void generate() throws GeneralSecurityException, IOException {
		// Generate the cert and key
		certKeyGen.generate(keysize);
		
		final X500Name x500Name = new X500Name(getCommonName(), getOrgUnitName(), 
				getOrgName(), getCity(), getState(), getCountry());
		
		// Save off the private key
		privateKey = certKeyGen.getPrivateKey();
		
		// Generate our self signed cert
		certificate = certKeyGen.getSelfCertificate(x500Name, new Date(), validity*24*60*60);
	}
	
	/**
	 * Set the info that will be used to generated the self-signed cert
	 * 
	 * @param commonName
	 * @param orgUnitName
	 * @param orgName
	 * @param city
	 * @param state
	 * @param country
	 */
	public void setCertificateInfo(String commonName, String orgUnitName, 
			String orgName, String city, String state, String country) {
		
		setCommonName(commonName);
		setOrgUnitName(orgUnitName);
		setOrgName(orgName);
		setCity(city);
		setState(state);
		setCountry(country);
	}
	
	/**
	 * Get the private key
	 * 
	 * @return
	 */
	public PrivateKey getPrivateKey() {
		return privateKey;
	}
	
	/**
	 * Get the self-signed certificate's public key
	 * 
	 * @return
	 */
	public PublicKey getPublicKey() {
		return certificate.getPublicKey();
	}
	
	/**
	 * Get the self-signed cert that was generated
	 * 
	 * @return
	 */
	public X509Certificate getCertificate() {
		return certificate;
	}
	
	public CertAndKeyGen getCertKeyGen() {
		return certKeyGen;
	}

	public String getCommonName() {
		return commonName;
	}

	public void setCommonName(String commonName) {
		this.commonName = commonName;
	}

	public String getOrgUnitName() {
		return orgUnitName;
	}

	public void setOrgUnitName(String orgUnitName) {
		this.orgUnitName = orgUnitName;
	}

	public String getOrgName() {
		return orgName;
	}

	public void setOrgName(String orgName) {
		this.orgName = orgName;
	}

	public String getCity() {
		return city;
	}

	public void setCity(String city) {
		this.city = city;
	}

	public String getState() {
		return state;
	}

	public void setState(String state) {
		this.state = state;
	}

	public String getCountry() {
		return country;
	}

	public void setCountry(String country) {
		this.country = country;
	}

	public int getValidity() {
		return validity;
	}

	/**
	 * Set how the self-signed cert will be valid for in days
	 * 
	 * @param validity
	 */
	public void setValidity(int validity) {
		this.validity = validity;
	}

	public int getKeysize() {
		return keysize;
	}

	protected void setKeysize(int keysize) {
		this.keysize = keysize;
	}
	
}
