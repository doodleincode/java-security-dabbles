package test;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Base64;

import org.junit.Before;
import org.junit.Test;

import net.awesomeapps.security.RSA;
import net.awesomeapps.security.RSAKeyPairGenerator;
import net.awesomeapps.security.RSASigner;
import net.awesomeapps.security.io.PemObject;
import net.awesomeapps.security.io.PemWriter;

public class SigningUnitTest {

	private byte[] message = "No one can change this without me knowing!".getBytes();
	RSAKeyPairGenerator generator;
	KeyPair keyPair;
	
	@Before
	public void setUp() throws Exception {
		generator = RSAKeyPairGenerator.getInstance(RSA.KEYSIZE_2048);
		keyPair = generator.generateKeyPair();
		
		// Write to file
		PemWriter.write(new File("signing_pub_key.pem"), new PemObject(keyPair.getPublic(), PemObject.ContentType.PUBLIC_KEY));
		PemWriter.write(new File("signing_pri_key.pem"), new PemObject(keyPair.getPrivate(), PemObject.ContentType.PRIVATE_KEY));
	}
	
	@Test
	public void testSigningShouldPass() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException {
		assert(sign() != null);
	}
	
	@Test
	public void testVerifyShouldPass() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException {
		byte[] signature = sign();
		
		assert(RSASigner.verify(message, signature, keyPair.getPublic()));
	}
	
	@Test
	public void testInvalidSignature() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException {
		byte[] signature = sign();
		
		// Alter the signature
		signature[0] = 0x01;
		signature[1] = 0x02;
		signature[2] = 0x03;
		
		assert(!RSASigner.verify(message, signature, keyPair.getPublic()));
	}
	
	@Test
	public void testWrongKey() throws NoSuchAlgorithmException, SignatureException, KeyException, IOException {
		byte[] signature = sign();
		
		// Create a new key
		KeyPair keyPair2 = generator.generateKeyPair();
		
		assert(!RSASigner.verify(message, signature, keyPair2.getPublic()));
	}
	
	private byte[] sign() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException {
		byte[] signature = RSASigner.sign(message, keyPair.getPrivate());
		
		// Write out to file
		try (BufferedWriter bw = new BufferedWriter(new FileWriter("signature.txt"))) {
			bw.write(Base64.getEncoder().encodeToString(signature));
		}
		
		return signature;
	}

}
