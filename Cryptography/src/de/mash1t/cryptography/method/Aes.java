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
package de.mash1t.cryptography.method;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import de.mash1t.cryptography.CryptoBasics;
import de.mash1t.cryptography.EncryptionMethod;
import de.mash1t.cryptography.crypter;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 * Encryption method AES
 * http://blog.axxg.de/java-aes-verschluesselung-mit-beispiel/
 * 
 * @author Manuel Schmid
 */
public class Aes extends EncryptionMethod implements crypter {

    private SecretKeySpec secretKeySpec;

    /**
     * Makes a new secretKeySpec from the SessionId
     */
    public Aes() {
        this.makeKey();
    }

    @Override
    public String encrypt(String message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // Encrypt bytes
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] encrypted = cipher.doFinal(message.getBytes());

        // Convert bytes to Base64-String
        BASE64Encoder myEncoder = new BASE64Encoder();

        // Result
        return myEncoder.encode(encrypted);
    }

    @Override
    public String decrypt(String message) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // BASE64 String zu Byte-Array konvertieren
        BASE64Decoder myDecoder2 = new BASE64Decoder();
        byte[] crypted2 = myDecoder2.decodeBuffer(message);

        // Entschluesseln
        Cipher cipher2 = Cipher.getInstance("AES");
        cipher2.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] cipherData2 = cipher2.doFinal(crypted2);
        String erg = new String(cipherData2);

        // Klartext
        return erg;
    }

    public boolean makeKey() {
        try {
            // Make Byte-Array out of session id
            byte[] key = sessionId.getBytes("UTF-8");
            // Create MD5 hash from array
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            // Create secret key
            // TODO Change SecretKeySpec creation
            key = sha.digest(key);
            key = Arrays.copyOf(key, CryptoBasics.encryption);
            this.secretKeySpec = new SecretKeySpec(key, "AES");
            return true;
        } catch (UnsupportedEncodingException | NoSuchAlgorithmException ex) {
            return false;
        }
    }
}
