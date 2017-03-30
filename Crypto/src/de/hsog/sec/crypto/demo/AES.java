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
		// TODO
		return null;
	}

	public static String decrypt(String strToDecrypt, String secret) {
		// TODO
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
