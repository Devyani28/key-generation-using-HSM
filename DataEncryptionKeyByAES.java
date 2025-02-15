package edu.keygeneration;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class DataEncryptionKeyByAES {

	public static void main(String[] args) {
		
		try {
			
		//KeyGenerator use for instance of AES
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256);
		
		//AES secretKey
		SecretKey secretKey = keyGen.generateKey();
		
		//AES as 64base encoded for readability
		String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        System.out.println("Generated AES Key (Base64): " + encodedKey);
        
        Cipher cipher = Cipher.getInstance("AES");
        
        //encryption
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        // Encrypt the message
        String originalMessage = "Original message";
        byte[] encryptedMessage = cipher.doFinal(originalMessage.getBytes());
        //msg encoded to base64 for readability
        String encryptedMessageBase64 = Base64.getEncoder().encodeToString(encryptedMessage);
        System.out.println("Encrypted Message (Base64): " + encryptedMessageBase64);
		
        
        //decryption
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        //decrypt the message
        byte[] decodedEncryptedMsg = Base64.getDecoder().decode(encryptedMessageBase64);
        byte[] decryptedMessage = cipher.doFinal(decodedEncryptedMsg);
        System.out.println("Decrypted Message = "+ new String(decryptedMessage));
        
		}catch(NoSuchAlgorithmException e) {
			System.err.println("Algorithm not found: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Encryption error: " + e.getMessage());
        }
	}

}
