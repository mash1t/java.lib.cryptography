/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.mash1t.cryptolib.method;

import de.mash1t.cryptolib.EncryptionMethod;
import de.mash1t.cryptolib.crypter;

/**
 * Encryption method caesar (shifting)
 *
 * @author Manuel Schmid
 */
public class Caesar extends EncryptionMethod implements crypter {

    private final int offset;

    /**
     * Sets a specific offset
     *
     * @param offset Offset to set
     */
    public Caesar(int offset) {
        this.offset = offset;
    }

    /**
     * Encrypt a String with a preset offset
     *
     * @param s String to encrypt
     * @return encrypted String
     */
    @Override
    public String encrypt(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char t = s.charAt(i);
            if (t >= 'A' && t <= 'Z') {
                int t1 = t - 'A' + this.offset;
                t1 = t1 % 26;
                sb.append((char) (t1 + 'A'));
            } else if (t >= 'a' && t <= 'z') {
                int t1 = t - 'a' + this.offset;
                t1 = t1 % 26;
                sb.append((char) (t1 + 'a'));
            } else {
                sb.append((char) t);
            }
        }
        return sb.toString();
    }

    /**
     * Decrypt a String with a preset offset
     *
     * @param s String to decrypt
     * @return decrypted String
     */
    @Override
    public String decrypt(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char t = s.charAt(i);
            if (t >= 'A' && t <= 'Z') {
                int t1 = t - 'A' - this.offset;
                if (t1 < 0) {
                    t1 = 26 + t1;
                }
                sb.append((char) (t1 + 'A'));
            } else if (t >= 'a' && t <= 'z') {
                int t1 = t - 'a' - this.offset;
                if (t1 < 0) {
                    t1 = 26 + t1;
                }
                sb.append((char) (t1 + 'a'));
            } else {
                sb.append((char) t);
            }
        }
        return sb.toString();
    }

    /**
     * Encrypt a String with a specific offset
     *
     * @param s String to encrypt
     * @param offset Offset to apply to the String
     * @return encrypted String
     */
    public static String encrypt(String s, int offset) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char t = s.charAt(i);
            if (t >= 'A' && t <= 'Z') {
                int t1 = t - 'A' + offset;
                t1 = t1 % 26;
                sb.append((char) (t1 + 'A'));
            } else if (t >= 'a' && t <= 'z') {
                int t1 = t - 'a' + offset;
                t1 = t1 % 26;
                sb.append((char) (t1 + 'a'));
            } else {
                sb.append((char) t);
            }
        }
        return sb.toString();
    }

    /**
     * Decrypt a String with a specific offset
     *
     * @param s String to decrypt
     * @param offset Offset to apply to the String
     * @return decrypted String
     */
    public static String decrypt(String s, int offset) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char t = s.charAt(i);
            if (t >= 'A' && t <= 'Z') {
                int t1 = t - 'A' - offset;
                if (t1 < 0) {
                    t1 = 26 + t1;
                }
                sb.append((char) (t1 + 'A'));
            } else if (t >= 'a' && t <= 'z') {
                int t1 = t - 'a' - offset;
                if (t1 < 0) {
                    t1 = 26 + t1;
                }
                sb.append((char) (t1 + 'a'));
            } else {
                sb.append((char) t);
            }
        }
        return sb.toString();
    }
}
