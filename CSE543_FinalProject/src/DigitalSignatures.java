import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.lang3.ArrayUtils;

public class DigitalSignatures {

	public static void main(String[] args) throws InvalidKeyException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, UnsupportedEncodingException {

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
		System.out.println("__________________________________________________________");
		System.out.println("Generated the Senders Pub/Priv RSA Keys");
		// Now that we have the private and public keys, lets encrypt message with the
		// private key of the sender to give us E(privateSender)[H(M)]
		byte[] encryptedHashM = encryptWithPrivateKey(senderKeys.getPrivateKey(), hashtext.getBytes());
		System.out.println("Encrypted the Hash(M) with the Private Key of the Sender. The length of this is: "
				+ encryptedHashM.length + " bytes");
		System.out.println("EprivateSender[H(M)] = " + Base64.getEncoder().encodeToString(encryptedHashM));

		System.out.println("__________________________________________________________");
		// Step 4 - pre-append the encrypted hash E(privateSender)[H(M)] to the message
		// M
		byte[] eHashWithM = ArrayUtils.addAll(encryptedHashM, message.getBytes());
		// This creates EprivateSender[H(M)]||M
		System.out.println("Created EprivateSender[H(M)]||M which is now " + eHashWithM.length + " bytes");
		System.out.println("EprivateSender[H(M)]||M = " + Base64.getEncoder().encodeToString(eHashWithM));
		System.out.println("__________________________________________________________");
		// Step 5 - Encrypt eHashWithM with the receiver's public key
		rsaKeyPairGenerator receiverKeys = new rsaKeyPairGenerator(); // Generate Receivers Pub/Priv Keys

		// Message too long! We must break it up!
		byte[] encryptedMessage = parseAndEncrypt(receiverKeys.getPublicKey(), eHashWithM);
		System.out.println("EncryptedMessage = " + encryptedMessage.length + " and message = "
				+ Base64.getEncoder().encodeToString(encryptedMessage));

		System.out.println("==========================================================");
		System.out.println("-----------------------SENDING MESSAGE--------------------");
		System.out.println("==========================================================");

		// -------------------------------------------------------------------------------------------------------------------------------
		// SENDER COMPLETE - message sent will be encryptedMessage
		// -------------------------------------------------------------------------------------------------------------------------------

		// Pretend sending of message via an open channel

		// -------------------------------------------------------------------------------------------------------------------------------
		// INITIATE RECEIVER
		// -------------------------------------------------------------------------------------------------------------------------------

		// Step 1 - Receive Message
		// Received message: encryptedMessage
		System.out.println("==========================================================");
		System.out.println("-----------------------RECIEVED MESSAGE-------------------");
		System.out.println("==========================================================");
		// Step 2 - Decrypt Message Received using receiver private key
		// Message too long to decrypt! We must break it up!
		byte[] decryptedMessage = parseAndDecrypt(receiverKeys.getPrivateKey(), encryptedMessage);
		System.out.println("The decryptedMessage is " + decryptedMessage.length + " bytes long");
		System.out.println("The decryptedMessage is " + Base64.getEncoder().encodeToString(decryptedMessage));
		System.out.println("__________________________________________________________");

		// Now we have: EprivateSender[H(M)]||M
		// Step 3 - Split into two separate messages EprivateSender[H(M)] and M
		// TODO figure out how to split, I assume since this is base64 we can grab the
		// first n bytes and use that as the deliminator
		byte[] pureMessageReceived = null; // this is just M
		pureMessageReceived = Arrays.copyOfRange(decryptedMessage, 512, decryptedMessage.length);
		System.out.println("Length of the pure message Received = " + pureMessageReceived.length);
		String plaintextMessageRecieved = new String(pureMessageReceived, "UTF-8");
		System.out.println("The pure message Recieved is = " + plaintextMessageRecieved);
		byte[] encryptedPrivSenderHash = Arrays.copyOfRange(decryptedMessage, 0, 512);// This is just
																						// EprivateSender[H(M)]
		System.out.println("Length of the encryptedHash Received = " + encryptedPrivSenderHash.length);
		System.out.println(
				"The encryptedHash Recieved is = " + Base64.getEncoder().encodeToString(encryptedPrivSenderHash));
		System.out.println("__________________________________________________________");

		// Step 4 - decrypt (using the senders Public Key) the encryptedPrivSenderHash
		// to reveal the hash the sender created.
		byte[] hashs = decryptWithPublicKey(senderKeys.getPublicKey(), encryptedPrivSenderHash);
		// hashs = hash sent to us
		// make hashs into a string
		String StringHashs = new String(hashs, "UTF-8");
		System.out.println("The hash recieved is " + StringHashs);
		System.out.println("__________________________________________________________");

		// Step 5 - Create our own hash of M
		// Turn pureMessageReceived into a string
		String hasho = createMd5Hash(plaintextMessageRecieved); // hasho is our hash we created from M
		System.out.println("Created a hash of the plaintextMessageRecieved = " + hasho);

		System.out.println("__________________________________________________________");
		// Step 6 - Verify that both hashes are the same
		if (StringHashs.equals(hasho)) {
			System.out.println("The hash matches!");
			System.out.println("The secret message reveived is: " + plaintextMessageRecieved);
		} else {
			System.out.println("Error: hashes did not match! ");
		}

		// -------------------------------------------------------------------------------------------------------------------------------
		// RECEIVER COMPLETE
		// -------------------------------------------------------------------------------------------------------------------------------

	}

	public static byte[] parseAndDecrypt(PrivateKey privateKey, byte[] ciphertext) throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		int c = 1;
		byte[] parsedTogether = null;
		int remainder = ciphertext.length % 512;
		for (int j = 0; j < Math.floorDiv(ciphertext.length, 512); j++) {
			byte[] temp = null;
			byte[] test = Arrays.copyOfRange(ciphertext, j, (c * 512));
			temp = decryptWithPrivateKey(privateKey, Arrays.copyOfRange(ciphertext, j * 512, (j * 512) + 512));
			parsedTogether = ArrayUtils.addAll(parsedTogether, temp);
		}
		if (remainder != 0) {
			byte[] temp = decryptWithPrivateKey(privateKey,
					Arrays.copyOfRange(ciphertext, ciphertext.length - remainder, ciphertext.length));
			parsedTogether = ArrayUtils.addAll(parsedTogether, temp);
		}
		return parsedTogether;
	}

	public static byte[] parseAndEncrypt(PublicKey publicKey, byte[] plaintext) throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		int c = 1;
		byte[] parsedTogether = null;
		int remainder = plaintext.length % 501;
		for (int j = 0; j < plaintext.length / 501; j++) {
			byte[] temp = null;
			temp = encryptWithPublicKey(publicKey, Arrays.copyOfRange(plaintext, j, c * 501));
			parsedTogether = ArrayUtils.addAll(parsedTogether, temp);
		}
		if (remainder != 0) {
			byte[] temp = encryptWithPublicKey(publicKey,
					Arrays.copyOfRange(plaintext, plaintext.length - remainder, plaintext.length));
			parsedTogether = ArrayUtils.addAll(parsedTogether, temp);
		}
		return parsedTogether;
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
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
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
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
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
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
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
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
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
