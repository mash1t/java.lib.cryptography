/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.mash1t.cryptolib.method;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author Manuel Schmid
 */
public class Rsa {

    // Keys
    private final PublicKey publicKey;
    private final PrivateKey privateKey;

    /**
     * Creates key pair and sets private SecretKeySpec
     *
     * @throws NoSuchAlgorithmException
     */
    public Rsa() throws NoSuchAlgorithmException {
        //Creates a new key pair of keys and sets them internally
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(512);
        KeyPair kp = kpg.genKeyPair();
        publicKey = kp.getPublic();
        privateKey = kp.getPrivate();
        // Create SecretKeySpec from private key
    }

    public static KeyPair getNewKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.genKeyPair();
        return kp;
    }

    public PublicKey getPublicKey() {
        return this.publicKey;
    }

    /**
     * Encrypt the plain text using public key.
     *
     * @param text : original plain text
     * @param key :The public key
     * @return Encrypted text
     */
    public static byte[] encrypt(String text, PublicKey key) {
        byte[] cipherText = null;
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            // get an RSA cipher object and print the provider
            final Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
            // encrypt the plain text using the public key
            cipher.init(Cipher.ENCRYPT_MODE, key);
            cipherText = cipher.doFinal(text.getBytes());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchProviderException e) {
            return null;
        }
        return cipherText;
    }

    /**
     * Decrypt text using private key.
     *
     * @param text
     * @return plain text
     */
    public String decrypt(byte[] text) {
        byte[] dectyptedText = null;
        try {
            // get an RSA cipher object and print the provider
            final Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");

            // decrypt the text using the private key
            cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
            dectyptedText = cipher.doFinal(text);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchProviderException ex) {
            return null;
        }

        return new String(dectyptedText);
    }

}
