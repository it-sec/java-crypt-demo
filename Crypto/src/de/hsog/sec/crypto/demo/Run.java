package de.hsog.sec.crypto.demo;

import java.security.NoSuchAlgorithmException;

import javax.crypto.NoSuchPaddingException;

public class Run {

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException {

		final String secretKey = "HochschuleOffenburg!";
		String originalString = "Vorlesung IT-Security";

		// DES
		String encryptedDESString = DES.encrypt(originalString, secretKey);
		String decryptedDESString = DES.decrypt(encryptedDESString, secretKey);

		System.out.println("Message to en- and decrypt: " +originalString);
		System.out.println("DES encrypted: "+encryptedDESString);
		System.out.println("DES decrypted: "+decryptedDESString);
		
		
		// AES
		String encryptedString = AES.encrypt(originalString, secretKey);
		String decryptedString = AES.decrypt(encryptedString, secretKey);

		System.out.println("AES encrypted: "+encryptedString);
		System.out.println("AES decrypted: "+decryptedString);
	}

}
