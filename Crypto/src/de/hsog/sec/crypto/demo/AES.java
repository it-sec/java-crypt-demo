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

public class AES {

	private static String salt = "Offenburg";

	public static String encrypt(String strToEncrypt, String secret) {
		try {
			// setKey(secret);
			SecretKey myKey = getSecretKey(secret, salt, "AES", 256);

			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, myKey);
			
			return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
		} catch (Exception e) {
			System.out.println("Error while encrypting: " + e.toString());
		}
		return null;
	}

	public static String decrypt(String strToDecrypt, String secret) {
		try {
			// setKey(secret);
			SecretKey myKey = getSecretKey(secret, salt, "AES", 256);
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
			
			cipher.init(Cipher.DECRYPT_MODE, myKey);
			return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
		} catch (Exception e) {
			System.out.println("Error while decrypting: " + e.toString());
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
