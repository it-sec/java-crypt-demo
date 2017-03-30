package de.hsog.sec.crypto.demo;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

public class Algorithms {

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException {

		System.out.println("\nSecurity-Provider:");
		for (Provider prov : Security.getProviders()) {
			System.out.println("  " + prov + ": " + prov.getInfo());
		}
		System.out.println("\nMaxAllowedKeyLength (fuer '" + Cipher.getInstance("AES").getProvider()
				+ "' mit aktuellen 'JCE Policy Files'):\n" + "  DES        = " + Cipher.getMaxAllowedKeyLength("DES")
				+ "\n" + "  Triple DES = " + Cipher.getMaxAllowedKeyLength("Triple DES") + "\n" + "  AES        = "
				+ Cipher.getMaxAllowedKeyLength("AES") + "\n" + "  Blowfish   = "
				+ Cipher.getMaxAllowedKeyLength("Blowfish") + "\n" + "  RSA        = "
				+ Cipher.getMaxAllowedKeyLength("RSA") + "\n");
	}

}
