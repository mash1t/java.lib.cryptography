/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.mash1t.cryptolib.method;

import com.sun.org.apache.xml.internal.security.utils.Base64;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import static sun.security.x509.CertificateAlgorithmId.ALGORITHM;

/**
 *
 * @author Manuel Schmid
 */
public class RsaTest {

        private final String base = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut l";
    
    @Test
    public void testObjectGeneration() throws NoSuchAlgorithmException {
        //Rsa rsa = new Rsa();
    }
    
    @Test 
    public void testEncryptionDecryption() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException{
                Rsa rsa = new Rsa();
                
                byte[] encrypted = Rsa.encrypt(base, rsa.getPublicKey());
                String decrypted = rsa.decrypt(encrypted);
    }
}
