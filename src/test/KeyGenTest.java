package test;

import java.io.File;
import java.io.IOException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import net.awesomeapps.security.RSA;
import net.awesomeapps.security.RSAKeyPairGenerator;
import net.awesomeapps.security.io.PemObject;
import net.awesomeapps.security.io.PemWriter;

public class KeyGenTest {

	public static void main(String[] args) {
		try {
			RSAKeyPairGenerator rsaKeyPairGen = RSAKeyPairGenerator.getInstance(RSA.KEYSIZE_2048);
			KeyPair keyPair = rsaKeyPairGen.generateKeyPair();
			
			PemObject publicKey = new PemObject(keyPair.getPublic(), PemObject.ContentType.PUBLIC_KEY);
			PemObject privateKey = new PemObject(keyPair.getPrivate(), PemObject.ContentType.RSA_PRIVATE_KEY);
			
			PemWriter.write(new File("publickey.pem"), publicKey);
			PemWriter.write(new File("privatekey.pem"), privateKey);
		} 
		catch (NoSuchAlgorithmException | IOException | KeyException e) {
			e.printStackTrace();
		}
		
	}

}
