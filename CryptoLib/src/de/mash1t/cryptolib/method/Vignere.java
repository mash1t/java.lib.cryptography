/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.mash1t.cryptolib.method;

import de.mash1t.cryptolib.EncryptionMethod;
import de.mash1t.cryptolib.crypter;

/**
 * Encryption method vignere (shifting)
 *
 * @author Manuel Schmid
 */
public class Vignere extends EncryptionMethod implements crypter {

    private final String key;

    public Vignere(String key) {
        this.key = key;
    }

    /**
     * Encrypt/Decrypt String
     *
     * @param plaintext String to encrypt/decrypt
     * @return encrypted/decrypted String
     */
    @Override
    public String encrypt(String plaintext) {

        final int textSize = plaintext.length();
        final int keySize = key.length();

        final StringBuilder encryptedText = new StringBuilder(textSize);
        for (int i = 0; i < textSize; i++) {
            final int plainNR = plaintext.codePointAt(i);
            final int keyNR = key.codePointAt(i % keySize);

            final long cipherNR;
            cipherNR = ((long) plainNR + (long) keyNR) & 0xFFFFFFFFL;
            
            encryptedText.appendCodePoint((int) cipherNR);
        }

        return encryptedText.toString();
    }
    
        /**
     * Encrypt/Decrypt String
     *
     * @param plaintext String to encrypt/decrypt
     * @return encrypted/decrypted String
     */
    @Override
    public String decrypt(String plaintext) {

        final int textSize = plaintext.length();
        final int keySize = key.length();

        final StringBuilder encryptedText = new StringBuilder(textSize);
        for (int i = 0; i < textSize; i++) {
            final int plainNR = plaintext.codePointAt(i);
            final int keyNR = key.codePointAt(i % keySize);

            final long cipherNR;
            cipherNR = ((long) plainNR - (long) keyNR) & 0xFFFFFFFFL;
            
            encryptedText.appendCodePoint((int) cipherNR);
        }

        return encryptedText.toString();
    }

    /**
     * Encrypt/Decrypt String
     *
     * @param plaintext String to encrypt/decrypt
     * @param key Key with which the String should be encrypted/decrypted
     * @param encrypt bollean if String should be encrypted/decrypted
     * @return encrypted/decrypted String
     */
    public static String crypt(String plaintext, String key, boolean encrypt) {

        final int textSize = plaintext.length();
        final int keySize = key.length();

        final StringBuilder encryptedText = new StringBuilder(textSize);
        for (int i = 0; i < textSize; i++) {
            final int plainNR = plaintext.codePointAt(i);
            final int keyNR = key.codePointAt(i % keySize);

            final long cipherNR;
            if (encrypt) {
                cipherNR = ((long) plainNR + (long) keyNR) & 0xFFFFFFFFL;
            } else {
                cipherNR = ((long) plainNR - (long) keyNR) & 0xFFFFFFFFL;
            }

            encryptedText.appendCodePoint((int) cipherNR);
        }

        return encryptedText.toString();
    }
}
