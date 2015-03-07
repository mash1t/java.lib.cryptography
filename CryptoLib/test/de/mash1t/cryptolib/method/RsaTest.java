package de.mash1t.cryptolib.method;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.openpgp.PGPException;
import org.junit.Test;

public class RsaTest {

    @Test
    public void genKeyPair() throws InvalidKeyException, NoSuchProviderException, SignatureException, IOException, PGPException, NoSuchAlgorithmException {
        Rsa rsa = new Rsa();
        rsa.generateKeyPair();
    }

    @Test
    public void encryptString() throws NoSuchProviderException, IOException, PGPException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Rsa rsa = new Rsa();
        String encrypted = rsa.encryptString("Hallo Du Da");
    }

    @Test
    public void decryptString() throws NoSuchProviderException, IOException, PGPException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Rsa rsa = new Rsa();
         String encrypted = rsa.encryptString("Hallo Du Da");
        String decrypted = rsa.decryptString(encrypted);
    }

}
