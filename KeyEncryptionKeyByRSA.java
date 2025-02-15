package edu.keygeneration;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class KeyEncryptionKeyByRSA {

	private static PublicKey publicKey;
	private static PrivateKey privateKey;

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public KeyEncryptionKeyByRSA() {
		try {
			// KeyPairGenerator use for instance of RSA
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			publicKey = keyPair.getPublic();
			privateKey = keyPair.getPrivate();
		} catch (Exception e) {
			System.err.println("Error generating RSA keys: " + e.getMessage());
		}
	}

	public static void main(String[] args) throws Exception {

		KeyEncryptionKeyByRSA keyGen = new KeyEncryptionKeyByRSA();
		// Initialize the Cipher with RSA encryption
		String msg = "Original Message";
		System.out.println("encryptedMsg = " + encrypt(msg,keyGen.getPublicKey()));
		System.out.println("decryptedMsg = " + decrypt(encrypt(msg, publicKey),keyGen.getPrivateKey()));
	}

	private static String encrypt(String msg, PublicKey publicKey) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);

		// Encrypt the message and return as Base64-encoded string
		byte[] encryptedMessage = cipher.doFinal(msg.getBytes());
		return Base64.getEncoder().encodeToString(encryptedMessage);
	}

	private static String decrypt(String encryptedMsg64Base, PrivateKey privateKey) {
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);

			// Decrypt the message and return as Base64-encoded string
			byte[] encryptedMessage = Base64.getDecoder().decode(encryptedMsg64Base);
			byte[] decryptedMessage = cipher.doFinal(encryptedMessage);
			return new String(decryptedMessage);
		} catch (Exception e) {
			return null;
		}
	}

}
