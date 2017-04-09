package test;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;

import org.junit.Before;
import org.junit.Test;

import net.awesomeapps.security.RSA;
import net.awesomeapps.security.RSAKeyPairGenerator;
import net.awesomeapps.security.RSASigner;
import net.awesomeapps.security.io.PemObject;
import net.awesomeapps.security.io.PemReader;
import net.awesomeapps.security.io.PemWriter;

public class PemFileUnitTest {

	PemObject pemObjectPubOrig;
	PemObject pemObjectPrivOrig;
	File pemFile1;
	File pemFile2;
	
	@Before
	public void setUp() throws Exception {
		RSAKeyPairGenerator rsaKeyPairGen = RSAKeyPairGenerator.getInstance(RSA.KEYSIZE_2048);
		KeyPair keyPair = rsaKeyPairGen.generateKeyPair();
		
		pemObjectPubOrig = new PemObject(keyPair.getPublic(), PemObject.ContentType.PUBLIC_KEY);
		pemObjectPrivOrig = new PemObject(keyPair.getPrivate(), PemObject.ContentType.RSA_PRIVATE_KEY);
		
		writeFile();
	}

	@Test
	public void testPemFileWrite() throws UnsupportedEncodingException, IOException {
		assert(pemFile1.exists());
		assert(pemFile2.exists());
	}
	
	@Test
	public void testPemFileRead() throws UnsupportedEncodingException, IOException, GeneralSecurityException {
		PemObject pemObjectPubFromRead = PemReader.read(pemFile1);
		PemObject pemObjectPrivFromRead = PemReader.read(pemFile2);
		
//		System.out.println(pemObjectPubFromRead.getContentType());
//		System.out.println(pemObjectPrivFromRead.getContentType());
		
		assert(Arrays.equals(pemObjectPubFromRead.getContent(), pemObjectPubOrig.getContent()));
		assert(Arrays.equals(pemObjectPrivFromRead.getContent(), pemObjectPrivOrig.getContent()));
	}
	
	@Test
	public void testRSASigning() throws IOException, GeneralSecurityException {
		// Message that was signed
		byte[] message = "No one can change this without me knowing!".getBytes();
		
		// Read in pem public key
		PemObject pemObjectPub = PemReader.read(new File("signing_pub_key.pem"));
		
		// Read signature file
		byte[] signature = Base64.getDecoder().decode(Files.readAllBytes(new File("signature.txt").toPath()));
		
		// Get publickey object from pem
		PublicKey pubKey = RSASigner.getPublicKey(pemObjectPub);
		
		assert(RSASigner.verify(message, signature, pubKey));
	}
	
	@Test
	public void testRSASigningInvalidKey() throws IOException, GeneralSecurityException {
		// Message that was signed
		byte[] message = "No one can change this without me knowing!".getBytes();
		
		// Read in pem public key
		PemObject pemObjectPub = PemReader.read(new File("publickey.pem"));
		
		// Read signature file
		byte[] signature = Base64.getDecoder().decode(Files.readAllBytes(new File("signature.txt").toPath()));
		
		// Get publickey object from pem
		PublicKey pubKey = RSASigner.getPublicKey(pemObjectPub);
		
		assert(!RSASigner.verify(message, signature, pubKey));
	}
	
	private void writeFile() throws UnsupportedEncodingException, IOException {
		pemFile1 = new File("publickey.pem");
		pemFile2 = new File("privatekey.pem");
		
		PemWriter.write(pemFile1, pemObjectPubOrig);
		PemWriter.write(pemFile2, pemObjectPrivOrig);
	}

}
