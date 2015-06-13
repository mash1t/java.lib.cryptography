/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.mash1t.cryptolib.method;

import de.mash1t.cryptolib.CryptoBasics;
import de.mash1t.cryptolib.EncryptionMethod;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Manuel Schmid
 */
public class CaesarTest {

    private final String base = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut l";

    /**
     * Test of caesar methods
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testCipher() throws Exception {
        System.out.println("Caesar");
        EncryptionMethod caesar = new Caesar(CryptoBasics.offset);
        String encrypted = caesar.encryptString(base);
        String decrypted = caesar.decryptString(encrypted);
        assertEquals(base, decrypted);
    }

    /**
     * Test of caesar methods
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testStatic() throws Exception {
        System.out.println("Caesar");
        String encrypted = Caesar.encrypt(base, CryptoBasics.offset);
        String decrypted = Caesar.decrypt(encrypted, CryptoBasics.offset);
        assertEquals(base, decrypted);
    }

}
