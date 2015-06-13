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
     * @param s String to encryptString
     * @return encrypted String
     */
    @Override
    public String encryptString(String s) {
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
     * @param s String to decryptString
     * @return decrypted String
     */
    @Override
    public String decryptString(String s) {
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
     * @param s String to encryptString
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
     * @param s String to decryptString
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
