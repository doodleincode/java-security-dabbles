package test;

import java.io.IOException;
import java.security.GeneralSecurityException;

import org.junit.Test;

import net.awesomeapps.security.AESLib;
import net.awesomeapps.security.AESLib.CipherIntegrityKeyPair;

public class AESLibUnitTest {

	private static String PASSWORD = "password";
	private static byte[] SALT = AESLib.generateSalt();
	private static String PLAIN_TEXT = "Hello World!!";
	
	@Test
	public void encryptShouldPass() {
		assert(encrypt(PLAIN_TEXT) != null);
	}
	
	@Test
	public void decryptShouldPass() {
		byte[] cipherTextBytes = encrypt(PLAIN_TEXT);
		assert(cipherTextBytes != null);
		
		byte[] plainTextBytes = decrypt(cipherTextBytes);
		assert(plainTextBytes != null);
		
		assert(PLAIN_TEXT.equals(new String(plainTextBytes)));
	}
	
	@Test
	public void decryptIntegrityShouldFail() {
		byte[] cipherTextBytes = encrypt(PLAIN_TEXT);
		assert(cipherTextBytes != null);
		
		// Alter the hmac bytes to force a fail
		cipherTextBytes[0] = 0x0a;
		cipherTextBytes[5] = 0x0b;
		cipherTextBytes[10] = 0x0c;
		
		// This should return null and throw exception with "Invalid HMAC"
		byte[] plainTextBytes = decrypt(cipherTextBytes);
		assert(plainTextBytes == null);
	}
	
	private byte[] encrypt(String plainText) {
		try {
			CipherIntegrityKeyPair ciKeyPair = AESLib.generateKeyFromPassword(PASSWORD, SALT);
			return AESLib.encrypt(plainText, ciKeyPair);
		} 
		catch (GeneralSecurityException | IOException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	private byte[] decrypt(byte[] cipherBytes) {
		try {
			CipherIntegrityKeyPair ciKeyPair = AESLib.generateKeyFromPassword(PASSWORD, SALT);
			return AESLib.decrypt(cipherBytes, ciKeyPair);
		} 
		catch (GeneralSecurityException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	@SuppressWarnings("unused")
	private void printBytes(byte[] data) {
		for (int i = 0; i < data.length; i++) {
			System.out.print(String.format("0x%02X ", data[i]));
		}
		
		System.out.println();
	}

}
