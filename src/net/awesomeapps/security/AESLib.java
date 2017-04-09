package net.awesomeapps.security;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

final public class AESLib {

	/**
	 * This class is a container for a cipher key and HMAC key. This is really just a 
	 * convienence class so that we don't have to manage/pass around two SecretKey objects.
	 *
	 */
	final public static class CipherIntegrityKeyPair {
		private SecretKey cipherKey;
		private SecretKey hmacKey;
		
		public CipherIntegrityKeyPair(SecretKey cipherKey, SecretKey hmacKey) {
			this.cipherKey = cipherKey;
			this.hmacKey = hmacKey;
		}
		
		public SecretKey getCipherKey() {
			return cipherKey;
		}
		
		public SecretKey getHmacKey() {
			return hmacKey;
		}
	}
	
	// Algo and specs for using AES as our cipher algo
	private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final String CIPHER = "AES";
    private static final int AES_KEY_LENGTH_BITS = 128;
    private static final int IV_LENGTH_BYTES = 16;
    
    // For our PBKDF2
    private static final int PBE_ITERATIONS = 40000;
    private static final int PBE_SALT_LENGTH_BYTES = 16;
    private static final String PBE_ALGORITHM = "PBKDF2WithHmacSHA1";

    // Algo and specs for integrity of the cipher text
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int HMAC_KEY_LENGTH_BITS = 256;
    
    /**
     * Generate a cryptographically strong key from a password/known string
     * 
     * @param password
     * 				The password or known string that will be used to generate a cryptographically strong key
     * @param salt
     * 				Random salt. Use {@link AESLib#generateSalt()}
     * @return
     * 				A CipherIntegrityKeyPair object to be used for encryption/decryption
     * @throws GeneralSecurityException
     */
    public static CipherIntegrityKeyPair generateKeyFromPassword(String password, byte[] salt) 
    		throws GeneralSecurityException {
    	
    	KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt,
                PBE_ITERATIONS, AES_KEY_LENGTH_BITS + HMAC_KEY_LENGTH_BITS);
		SecretKeyFactory keyFactory = SecretKeyFactory
		        .getInstance(PBE_ALGORITHM);
		
		// Generate the actual bytes that will be used to create the keys
		byte[] keyBytes = keyFactory.generateSecret(keySpec).getEncoded();
		
		// Get the generate bytes for each key
		byte[] cipherKeyBytes = Arrays.copyOfRange(keyBytes, 0, AES_KEY_LENGTH_BITS/8);
		byte[] hmacKeyBytes = Arrays.copyOfRange(keyBytes, AES_KEY_LENGTH_BITS/8, keyBytes.length);

        return new CipherIntegrityKeyPair(
        		new SecretKeySpec(cipherKeyBytes, CIPHER),
        		new SecretKeySpec(hmacKeyBytes, HMAC_ALGORITHM)
        	);
    }
    
    /**
     * Encrypts the given plain text string with the given key. This method embedded a HMAC for
     * integrity validation when decrypting.
     * 
     * @param plainText
     * 				The plain text string to encrypt
     * @param keyPair
     * 				A CipherIntegrityKeyPair object. Use {@link AESLib#generateKeyFromPassword(String, byte[])}
     * @return
     * 				A byte array with format: HMAC(cipher text) + random IV + ciper text
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public static byte[] encrypt(String plainText, CipherIntegrityKeyPair keyPair) 
    		throws GeneralSecurityException, IOException  {
    	
    	return encrypt(plainText.getBytes("UTF-8"), keyPair);
    }
    
    /**
     * Same as {@link AESLib#encrypt(String, CipherIntegrityKeyPair)} but accepts a byte array plain text
     * 
     * @param plainText
     * 				The plain text byte array to encrypt
     * @param keyPair
     * 				A CipherIntegrityKeyPair object. Use {@link AESLib#generateKeyFromPassword(String, byte[])}
     * @return
     * 				A byte array with format: HMAC(cipher text) + random IV + ciper text
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public static byte[] encrypt(byte[] plainText, CipherIntegrityKeyPair keyPair) 
    		throws GeneralSecurityException, IOException  {
    	
		byte[] ivBytes = generateIv();
		
		Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
		cipher.init(Cipher.ENCRYPT_MODE, keyPair.getCipherKey(), new IvParameterSpec(ivBytes));
		
		byte[] cipherTextBytes = cipher.doFinal(plainText);
		byte[] hmacBytes = generateHmac(cipherTextBytes, keyPair.getHmacKey());
		
		// Result will be hmac + iv + ciphertext
		ByteArrayOutputStream os = new ByteArrayOutputStream( );
		os.write(hmacBytes);
		os.write(ivBytes);
		os.write(cipherTextBytes);
		
		return os.toByteArray();
    }
    
    /**
     * Decrypts the given byte array cipher text.
     * 
     * @param cipherText
     * 				The ciper text to try and decrypt
     * @param keyPair
     * 				A CipherIntegrityKeyPair object. Use {@link AESLib#generateKeyFromPassword(String, byte[])}
     * @return
     * 				The decrypted plain text
     * @throws GeneralSecurityException
     */
    public static byte[] decrypt(byte[] cipherText, CipherIntegrityKeyPair keyPair) 
    		throws GeneralSecurityException {
    	
		// Make sure the byte array is at least as long as the hmac and iv
		if (cipherText.length < (HMAC_KEY_LENGTH_BITS / 8) + IV_LENGTH_BYTES) {
			throw new GeneralSecurityException("Invalid cipher text length.");
		}
		
		// Extract the hmac, iv, and ciphertext
		byte[] hmacBytes = copyOfRange(cipherText, 0, HMAC_KEY_LENGTH_BITS/8);
		byte[] ivBytes = copyOfRange(cipherText, HMAC_KEY_LENGTH_BITS/8, IV_LENGTH_BYTES);
		byte[] cipherTextBytes = Arrays.copyOfRange(cipherText, 
				(HMAC_KEY_LENGTH_BITS/8) + IV_LENGTH_BYTES, cipherText.length);
		
		// Compute the hmac to check against the hmac given
		byte[] computedHmac = generateHmac(cipherTextBytes, keyPair.getHmacKey());
		
		// Make sure the hmac's are equal
		if (!constantTimeCompare(hmacBytes, computedHmac)) {
			throw new GeneralSecurityException("Invalid HMAC.");
		}
		
		Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
		cipher.init(Cipher.DECRYPT_MODE, keyPair.getCipherKey(), new IvParameterSpec(ivBytes));
		
		return cipher.doFinal(cipherTextBytes);
    }
    
    /**
     * Generate an HMAC on the given bytes using the given key
     * 
     * @param bytes
     * 				The bytes to generate a HMAC on.
     * @param key
     * 				A SecretKey object to use to generate the HMAC
     * @return
     * 				The resulting HMAC
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static byte[] generateHmac(byte[] bytes, SecretKey key) 
    		throws NoSuchAlgorithmException, InvalidKeyException {
    	
        Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
        hmac.init(key);
        
        return hmac.doFinal(bytes);
    }
    
    /**
     * Create a salt. This uses {@link AESLib#randomBytes(int)} with our 
     * predefined salt length of {@link AESLib#PBE_SALT_LENGTH_BYTES}
     * 
     * @return
     */
    public static byte[] generateSalt() {
    	return randomBytes(PBE_SALT_LENGTH_BYTES);
    }
    
    /**
     * Create an IV. This uses {@link AESLib#randomBytes(int)} with our 
     * predefined salt length of {@link AESLib#IV_LENGTH_BYTES}
     * 
     * @return
     */
    public static byte[] generateIv() {
		return randomBytes(IV_LENGTH_BYTES);
    }
    
    /**
     * Generate random bytes suitable for cryptographic use
     * 
     * @param length
     * 			Number of bytes to generate
     * @return
     */
    public static byte[] randomBytes(int length) {
		SecureRandom random = new SecureRandom();
		byte[] b = new byte[length];
		random.nextBytes(b);
		
		return b;
    }
    
    /**
     * Basically a substring function for byte array. Works a little easier than the built-in
     * {@link Arrays#copyOfRange(byte[], int, int)}
     * 
     * This uses {@link Arrays#copyOfRange(byte[], int, int)} under the hood and as such could throw
     * ArrayIndexOutOfBoundsException, IllegalArgumentException, or NullPointerException
     * 
     * @param src
     * 			The byte array to slice
     * @param start
     * 			Index of where to start slicing
     * @param length
     * 			Number of bytes to slice
     * @return
     * 			A new array containing the specified range from the original array
     */
    private static byte[] copyOfRange(byte[] src, int start, int length) {
    	return Arrays.copyOfRange(src, start, start + length);
    }
    
    /**
     * Performs a constant time comparison to help mitigate side channel attacks
     * 
     * @param b1
     * @param b2
     * @return
     */
    private static boolean constantTimeCompare(byte[] b1, byte[] b2) {
		if (b1.length != b2.length) {
			return false;
		}
		
		int result = 0;
		
		for (int i = 0; i < b1.length; i++) {
			result |= b1[i] ^ b2[i];
		}
		
		return result == 0;
	}
    
}
