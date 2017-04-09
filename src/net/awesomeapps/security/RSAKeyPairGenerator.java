package net.awesomeapps.security;

import java.security.KeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * Generates a RSA key pair.
 * 
 */
public class RSAKeyPairGenerator {
	
	private int keysize;
	private KeyPairGenerator generator;
	
	protected RSAKeyPairGenerator(int keysize, KeyPairGenerator generator) {
		this.keysize = keysize;
		this.generator = generator;
	}
	
	/**
	 * Create an instance of {@link RSAKeyPairGenerator} using the specified keysize.
	 * 
	 * @param keysize
	 * 				Can be one of {@link RSA#KEYSIZE_2048} or {@link RSA#KEYSIZE_4096}
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static RSAKeyPairGenerator getInstance(int keysize) throws NoSuchAlgorithmException {
		// Create instance of our RSA key pair generator
		RSAKeyPairGenerator rsa = new RSAKeyPairGenerator(keysize, KeyPairGenerator.getInstance(RSA.KEY_ALGO));
		
		// Initialize the keypair generator
		rsa.getGenerator().initialize(keysize);
		
		return rsa;
	}
	
	/**
	 * Generate the keypair. Will throw {@link KeyException} if for some reason generating the
	 * key results in a null value.
	 * 
	 * @return
	 * @throws KeyException 
	 */
	public KeyPair generateKeyPair() throws KeyException {
		KeyPair keyPair = generator.generateKeyPair();
		
		if (keyPair == null) {
			throw new KeyException("Unable to generate keypair");
		}
		
		return keyPair;
	}

	/**
	 * Get the keysize used to generate the keypair
	 * 
	 * @return
	 */
	public int getKeysize() {
		return keysize;
	}

	/**
	 * Get the KeyPairGenerator object that was used to generate the RSA keypair
	 * 
	 * @return
	 */
	public KeyPairGenerator getGenerator() {
		return generator;
	}
	
}
