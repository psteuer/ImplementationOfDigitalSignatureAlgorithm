import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.lang3.ArrayUtils;

public class DigitalSignatures {

	public static void main(String[] args) throws InvalidKeyException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException {

		// -------------------------------------------------------------------------------------------------------------------------------
		// INITIATE SENDER
		// -------------------------------------------------------------------------------------------------------------------------------

		// Step 1: Create message M
		String message = "KeepMeSecret";
		System.out.println("Message: " + message);
		// Step 2: Generate a hash of the message M(m) using md5
		String hashtext = createMd5Hash(message);
		System.out.println("The hash of the message is H(M) = " + hashtext);

		// Step 3 - Encrypt the message with the private key K(PrivateSender) generated
		// with RSA
		rsaKeyPairGenerator senderKeys = new rsaKeyPairGenerator(); // Generate Senders Pub/Priv Keys
		// Now that we have the private and public keys, lets encrypt message with the
		// private key of the sender to give us E(privateSender)[H(M)]
		byte[] encryptedHashM = encryptWithPrivateKey(senderKeys.getPrivateKey(), hashtext.getBytes());

		// Step 4 - pre-append the encrypted hash E(privateSender)[H(M)] to the message
		// M
		byte[] eHashWithM = ArrayUtils.addAll(encryptedHashM, message.getBytes());
		// This creates EprivateSender[H(M)]||M

		// Step 5 - Encrypt eHashWithM with the receiver's public key
		rsaKeyPairGenerator receiverKeys = new rsaKeyPairGenerator(); // Generate Receivers Pub/Priv Keys
		byte[] encryptedMessage = encryptWithPublicKey(receiverKeys.getPublicKey(), eHashWithM);

		// -------------------------------------------------------------------------------------------------------------------------------
		// SENDER COMPLETE - message sent will be encryptedMessage
		// -------------------------------------------------------------------------------------------------------------------------------

		//Pretend sending of message via an open channel 
		
		// -------------------------------------------------------------------------------------------------------------------------------
		// INITIATE RECEIVER
		// -------------------------------------------------------------------------------------------------------------------------------

		// Step 1 - Receive Message
		// Received message: encryptedMessage

		// Step 2 - Decrypt Message Received using receiver private key
		byte[] decryptedMessage = decryptWithPrivateKey(receiverKeys.getPrivateKey(), encryptedMessage);
		// Now we have: EprivateSender[H(M)]||M
		// Step 3 - Split into two separate messages EprivateSender[H(M)] and M
		// TODO figure out how to split, I assume since this is base64 we can grab the
		// first n bytes and use that as the deliminator
		byte[] pureMessageReceived = null; // this is just M
		byte[] encryptedPrivSenderHash = null;// This is just EprivateSender[H(M)]
		// Step 4 - decrypt (using the senders Public Key) the encryptedPrivSenderHash
		// to reveal the hash the sender created.
		byte[] hashs = decryptWithPublicKey(senderKeys.getPublicKey(), encryptedPrivSenderHash);
		// hashs = hash sent to
		// us
		// make hashs into a string
		String StringHashs = Base64.getEncoder().encodeToString(hashs);

		// Step 5 - Create our own hash of M
		// Turn pureMessageReceived into a string
		String StringPureMessageReceived = Base64.getEncoder().encodeToString(pureMessageReceived);

		String hasho = createMd5Hash(StringPureMessageReceived); // hasho is our hash we created from M

		// Step 6 - Verify that both hashes are the same
		if (StringHashs.equals(hasho)) {
			System.out.println("The hash matches!");
			System.out.println("The secret message reveived is:" + StringPureMessageReceived);
		} else {
			System.out.println("Error: hashes did not match! ");
		}

		// -------------------------------------------------------------------------------------------------------------------------------
		// RECEIVER COMPLETE
		// -------------------------------------------------------------------------------------------------------------------------------

	}

	/**
	 * Encrypts the plaintext message with a PrivateKey
	 * 
	 * @param key
	 * @param plaintext
	 * @return Encrypted message in bytes
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] encryptWithPrivateKey(PrivateKey key, byte[] plaintext) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(plaintext);
	}

	/**
	 * Encrypts the plaintext message with a PublicKey
	 * 
	 * @param key
	 * @param plaintext
	 * @return Encrypted message in bytes
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] encryptWithPublicKey(PublicKey key, byte[] plaintext) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(plaintext);
	}

	/**
	 * Decypts the ciphertext with a private key
	 * 
	 * @param key
	 * @param ciphertext
	 * @return decrypted message in bytes
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] decryptWithPrivateKey(PrivateKey key, byte[] ciphertext) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(ciphertext);
	}

	/**
	 * Decypts the ciphertext with a public key
	 * 
	 * @param key
	 * @param ciphertext
	 * @return decrypted message in bytes
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] decryptWithPublicKey(PublicKey key, byte[] ciphertext) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(ciphertext);
	}

	/**
	 * Creates a md5 hash of the input string
	 * 
	 * @param input
	 * @return md5 hash of the input
	 */
	public static String createMd5Hash(String input) {
		try {

			// Static getInstance method is called with hashing MD5
			MessageDigest md = MessageDigest.getInstance("MD5");

			// digest() method is called to calculate message digest
			// of an input digest() return array of byte
			byte[] messageDigest = md.digest(input.getBytes());

			// Convert byte array into signum representation
			BigInteger no = new BigInteger(1, messageDigest);

			// Convert message digest into hex value
			String hashtext = no.toString(16);
			while (hashtext.length() < 32) {
				hashtext = "0" + hashtext;
			}
			return hashtext;
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Failed to create message digest");
		}
		return null;
	}
}
