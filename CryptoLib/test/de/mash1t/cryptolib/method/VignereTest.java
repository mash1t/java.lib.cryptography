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
public class VignereTest {

    private final String base = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut l";

    /**
     * Test of vignere crypt method
     */
    @Test
    public void testObject() throws Exception {
        System.out.println("Vignere");
        EncryptionMethod vignere = new Vignere(CryptoBasics.key);
        String encrypted = vignere.encrypt(base);
        String decrypted = vignere.decrypt(encrypted);
        assertEquals(base, decrypted);
    }

    /**
     * Test of vignere crypt method
     */
    @Test
    public void testStatic() {
        System.out.println("Vignere");
        String encrypted = Vignere.crypt(base, CryptoBasics.key, true);
        String decrypted = Vignere.crypt(encrypted, CryptoBasics.key, false);
        assertEquals(base, decrypted);
    }

}
