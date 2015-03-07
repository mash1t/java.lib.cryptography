/*
 * The MIT License
 *
 * Copyright 2015 Manuel Schmid.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
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
     * @param plaintext String to encryptString/decryptString
     * @return encrypted/decrypted String
     */
    @Override
    public String encryptString(String plaintext) {

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
     * @param plaintext String to encryptString/decryptString
     * @return encrypted/decrypted String
     */
    @Override
    public String decryptString(String plaintext) {

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
     * @param plaintext String to encryptString/decryptString
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
