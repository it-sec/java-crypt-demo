package de.hsog.sec.crypto.demo;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class DES {
	private static String salt = "Offenburg";

	public static String encrypt(String strToEncrypt, String secret) {
		try {

			// create SecretKey from PlainText
			SecretKey myKey = getSecretKey(secret, salt, "DES", 64);

			// Create the cipher
			Cipher desCipher;
			desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

			// Initialize the cipher for decryption
			desCipher.init(Cipher.ENCRYPT_MODE, myKey);

			// Decrypt the text
			byte[] textEncrypted = desCipher.doFinal(strToEncrypt.getBytes("UTF-8"));
			return Base64.getEncoder().encodeToString(textEncrypted);
			
		} catch (Exception e) {
			System.out.println("Error while encrypting: " + e.toString());
		}
		return null;
	}
	
	public static String decrypt(String strToDecrypt, String secret) {
		try {

			// create SecretKey from PlainText
			SecretKey myKey = getSecretKey(secret, salt, "DES", 64);

			// Create the cipher
			Cipher desCipher;
			desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

			// Initialize the cipher for decryption
			desCipher.init(Cipher.DECRYPT_MODE, myKey);

			// Decrypt the text
			byte[] textDecrypted = desCipher.doFinal(Base64.getDecoder().decode(strToDecrypt));
			return new String(textDecrypted);
			
		} catch (Exception e) {
			System.out.println("Error while encrypting: " + e.toString());
		}
		return null;
	}

	/*
	 * Derive the key, given password and salt.
	 */
	private static SecretKey getSecretKey(String mySecret, String salt, String algo, int keyLength)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		KeySpec spec = new PBEKeySpec(mySecret.toCharArray(), salt.getBytes(), 65536, keyLength);
		SecretKey tmp = factory.generateSecret(spec);
		SecretKey secret = new SecretKeySpec(tmp.getEncoded(), algo);

		return secret;
	}
}