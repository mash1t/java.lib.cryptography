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

import de.mash1t.cryptolib.rsa.PgpHelper;
import de.mash1t.cryptolib.rsa.RSAKeyPairGenerator;
import de.mash1t.cryptolib.crypter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;

/**
 *
 * @author Manuel Schmid
 */
public class Rsa implements crypter {

    private final boolean isArmored = false;
    private String id = "mash1t";
    private String passwd = "test123";
    private final boolean integrityCheck = true;

    protected final String publicKeyFileName = "pub.dat";
    protected final String privateKeyFileName = "private";
    
    private String publicKeyFile = publicKeyFileName;
    private String privateKeyFile = privateKeyFileName;

    /**
     * Ret
     *
     * @return
     * @throws java.io.FileNotFoundException
     * @throws org.bouncycastle.openpgp.PGPException
     */
    public PGPPublicKey getPublicKey() throws FileNotFoundException, IOException, PGPException {
        // TODO read from file when not set
        FileInputStream pubKeyInStream = new FileInputStream(publicKeyFile);
        return PgpHelper.getInstance().readPublicKey(pubKeyInStream);
    }

    /**
     *  Generates public and private key files with preset credentials written to preset paths. Not recommended to use
     * this method due to similar id/password shared with other generated keys for other users except you know what you
     * do
     *
     * @throws InvalidKeyException
     * @throws NoSuchProviderException
     * @throws SignatureException
     * @throws IOException
     * @throws PGPException
     * @throws NoSuchAlgorithmException
     */
    public void generateKeyPair() throws InvalidKeyException, NoSuchProviderException, SignatureException, IOException, PGPException, NoSuchAlgorithmException {

        // Initialize keygen and generate keys
        RSAKeyPairGenerator keyPairGen = new RSAKeyPairGenerator();
        KeyPair keyPair = keyPairGen.generateKeyPair();
        // Export keys to file
        FileOutputStream out1 = new FileOutputStream(privateKeyFile);
        FileOutputStream out2 = new FileOutputStream(publicKeyFile);
        keyPairGen.exportKeyPair(out1, out2, keyPair.getPublic(), keyPair.getPrivate(), id, passwd.toCharArray(), isArmored);
    }

    /**
     * Generates public and private key files with preset credentials written to the given paths. Not recommended to use
     * this method due to similar id/password shared with other generated keys for other users except you know what you
     * do
     *
     * @param keyFilePath path where the public key file is created at (with directory separator at the end)
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws IOException
     * @throws PGPException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public void generateKeyPairFiles(String keyFilePath) throws InvalidKeyException, SignatureException, IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException {
        this.publicKeyFile = keyFilePath + publicKeyFileName;
        this.privateKeyFile = keyFilePath + privateKeyFileName;
        this.generateKeyPair();
    }

    /**
     * Generates public and private key files with the given credentials written to preset paths
     *
     * @param id username for setting up PGPSecretKey
     * @param password password for setting up PGPSecretKey
     * @throws InvalidKeyException
     * @throws NoSuchProviderException
     * @throws SignatureException
     * @throws IOException
     * @throws PGPException
     * @throws NoSuchAlgorithmException
     */
    public void generateKeyPairFiles(String id, String password) throws InvalidKeyException, NoSuchProviderException, SignatureException, IOException, PGPException, NoSuchAlgorithmException {
        this.id = id;
        this.passwd = password;
        this.generateKeyPair();
    }

    /**
     * Generates public and private key files with the given credentials written to the given paths
     *
     * @param publicKeyFilePath path where the public key file is created at
     * @param privateKeyFilePath path where the private key file is created at
     * @param id username for setting up PGPSecretKey
     * @param password password for setting up PGPSecretKey
     * @throws InvalidKeyException
     * @throws NoSuchProviderException
     * @throws SignatureException
     * @throws IOException
     * @throws PGPException
     * @throws NoSuchAlgorithmException
     */
    public void generateKeyPairFiles(String publicKeyFilePath, String privateKeyFilePath, String id, String password) throws InvalidKeyException, NoSuchProviderException, SignatureException, IOException, PGPException, NoSuchAlgorithmException {
        this.publicKeyFile = publicKeyFilePath;
        this.privateKeyFile = privateKeyFilePath;
        this.id = id;
        this.passwd = password;
        this.generateKeyPair();
    }

    /**
     * Encrypts a file and creates crypted file
     *
     * @param plainPath path to the plain (unencrypted) file
     * @param cryptedPath path to where the crypted file should be created at
     * @throws NoSuchProviderException
     * @throws IOException
     * @throws PGPException
     */
    public void encryptFile(String plainPath, String cryptedPath) throws NoSuchProviderException, IOException, PGPException {
        FileInputStream pubKeyInStream = new FileInputStream(publicKeyFile);
        FileOutputStream cipheredFileOutStream = new FileOutputStream(cryptedPath);
        PgpHelper.getInstance().encryptFile(cipheredFileOutStream, plainPath, PgpHelper.getInstance().readPublicKey(pubKeyInStream), isArmored, integrityCheck);
        cipheredFileOutStream.close();
        pubKeyInStream.close();
    }

    /**
     * Decrypts a file and creates decrypted file
     *
     * @param cryptedPath path to where the crypted file should be created at
     * @param decryptedPath path to the decrypted file
     * @throws NoSuchProviderException
     * @throws IOException
     * @throws PGPException
     */
    public void decryptFile(String cryptedPath, String decryptedPath) throws FileNotFoundException, IOException, PGPException, NoSuchProviderException {

        FileInputStream cryptedFileInStream = new FileInputStream(cryptedPath);
        FileInputStream privKeyIn = new FileInputStream(privateKeyFile);
        FileOutputStream plainTextFileIs = new FileOutputStream(decryptedPath);
        PgpHelper.getInstance().decryptFile(cryptedFileInStream, plainTextFileIs, privKeyIn, passwd.toCharArray());
        cryptedFileInStream.close();
        plainTextFileIs.close();
        privKeyIn.close();
    }

//    @Override
    public synchronized void encrypt(String message) throws FileNotFoundException, IOException, NoSuchProviderException, PGPException {
        FileOutputStream stringOutStream = new FileOutputStream("temp.txt");
        stringOutStream.write(message.getBytes());
        stringOutStream.close();

        encryptFile("temp.txt", "crypted.txt");
        decryptFile("crypted.txt", "tempxxx.txt");
    }

    @Override
    public String decryptString(String message) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, NoSuchProviderException, PGPException {
        /**
         * Decrypts a file and creates decrypted file
         *
         * @param cryptedPath path to where the crypted file should be created at
         * @param decryptedPath path to the decrypted file
         * @throws NoSuchProviderException
         * @throws IOException
         * @throws PGPException
         */
    public void decryptString(String encrypted) throws FileNotFoundException, IOException, PGPException, NoSuchProviderException {

        FileInputStream privKeyIn = new FileInputStream(privateKeyFile);
        String decrypted = PgpHelper.getInstance().decryptString(encrypted, privKeyIn, passwd.toCharArray());
        privKeyIn.close();
        return encrypted;

    }

    @Override
    public synchronized String encryptString(String message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, NoSuchProviderException, PGPException {
        FileInputStream pubKeyInStream = new FileInputStream(publicKeyFile);
        String encrypted = PgpHelper.getInstance().encryptString(message, PgpHelper.getInstance().readPublicKey(pubKeyInStream), true, true);
        pubKeyInStream.close();
        return encrypted;
    }
}
