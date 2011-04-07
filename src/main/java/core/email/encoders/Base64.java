/*
 * Oxford Brookes University Secure Email Proxy 
 * Copyright (C) 2002/3 Oxford Brookes University Secure Email Project
 * http://secemail.brookes.ac.uk
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 * 
 * The Secure Email Project is:
 * 
 * Marcus Povey <mpovey@brookes.ac.uk> or <icewing@dushka.co.uk>
 * Damian Branigan <dbranigan@brookes.ac.uk>
 * George Davson <gdavson@brookes.ac.uk>
 * David Duce <daduce@brookes.ac.uk>
 * Simon Hogg <simon.hogg@brookes.ac.uk>
 * Faye Mitchell <frmitchell@brookes.ac.uk>
 * 
 * For further information visit the secure email project website.
 */

package core.email.encoders;
import java.io.ByteArrayOutputStream;

/**
 * <p>A class that contains utility methods for encoding and decoding binary data to and from
 * Base 64 MIME encoding. </p>
 */
public class Base64 {
    
    /** The maximum line length */
    private static final int MAX_LINE_LENGTH = 48;
    
    /** A lookup table for converting a 6 bit number block into its radix 64 encoded value. */
    private final static char[] encodeLUT = {
        'A','B','C','D','E','F','G','H',
        'I','J','K','L','M','N','O','P',
        'Q','R','S','T','U','V','W','X',
        'Y','Z','a','b','c','d','e','f',
        'g','h','i','j','k','l','m','n',
        'o','p','q','r','s','t','u','v',
        'w','x','y','z','0','1','2','3',
        '4','5','6','7','8','9','+','/'
    };
    
    /** A lookup table to convert a Radix 64 char to a 6 bit integer. */
    protected static final byte[] decodeLUT = 
    { 
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
        -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
        -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    };
    
    /**
     * <p>Takes an array of bytes and encodes them to base 64.</p>
     */
    public static byte[] encode(byte data[]) {
        
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        // encode
        int n = 0;
        byte a, b, c; // bytes to process (we process three bytes at a time)
        for (int cnt = 0; cnt < data.length/3; cnt++) {
            a = data[n++];
            b = data[n++];
            c = data[n++];
            
            out.write(encodeLUT[(a >>> 2) & 0x3F]);
            out.write(encodeLUT[((a << 4) & 0x30) + ((b >>> 4) & 0x0F)]);
            out.write(encodeLUT[((b << 2) & 0x3C) + ((c >>> 6) & 0x03)]);
            out.write(encodeLUT[c & 0x3F]); 
            
            if (n % MAX_LINE_LENGTH == 0) {
                out.write('\r');
                out.write('\n');
            }
        }
        
        // process any remainder.
        int remain = data.length % 3; // how much padding we need to add at the end.
        if (remain == 1) {
            a = data[n++];
            
            out.write(encodeLUT[(a >>> 2) & 0x3F]);
            out.write(encodeLUT[((a << 4) & 0x30)]); 
            out.write('=');
            out.write('=');
        } else if (remain == 2) {
            a = data[n++];
            b = data[n++];
            
            out.write(encodeLUT[(a >>> 2) & 0x3F]); 
            out.write(encodeLUT[((a << 4) & 0x30) + ((b >>> 4) & 0x0F)]);
            out.write(encodeLUT[((b << 2) & 0x3C)]); 
            out.write('='); 
        }
        if (n == 0 || n % MAX_LINE_LENGTH != 0) {
            out.write('\r');
            out.write('\n');
        }
        
        return out.toByteArray();
    }
    
    /**
     * <p>Takes the base64 encoded form of the packet and returns the raw encoded form.</p>
     * <p>Whitespace and all other unrecognised characters are ignored.</p>
     * @throws IllegalArgumentException if the data passed contained invalid characters or is the wrong length.
     */
    public static byte[] decode(byte data[]) {
        
        int padCount = 0;
        int realLength = 0;

        for (int cnt = 0; cnt < data.length; cnt++)
        {
            if (data[cnt] > ' ')
                realLength++;

            if (data[cnt] == '=') 
                padCount++;
        }

        if (realLength % 4 != 0)
            throw new IllegalArgumentException("The PGP message is not correctly Radix64 encoded!");
        
        int cnt = 0;
        int outputIndex = 0;
        int n = 0;
        byte[] t = new byte[4]; t[0] = t[1] = t[2] = t[3] = '=';
        byte[] ret = new byte[(realLength/4)*3 - padCount];
        
        while (cnt < data.length)
        {
            byte c = data[cnt++];
            if (c > ' ')
                t[n++] = c;
            
            if (n == 4)
            {
                outputIndex += decode(ret, outputIndex, t[0],t[1],t[2],t[3]);
                n = 0;
                t[0] = t[1] = t[2] = t[3] = '=';
            }
            
        }
        if (n > 0)
            decode(ret, outputIndex, t[0], t[1], t[2], t[3]);

        return ret;
    }
       
    /** Base64 decode a block of 4 bytes. */
    private static int decode(byte[] ret, int ret_off, byte a, byte b, byte c, byte d)
    {
        byte da = decodeLUT[a];
        byte db = decodeLUT[b];
        byte dc = decodeLUT[c];
        byte dd = decodeLUT[d];

        if (da == -1 || db == -1 || (dc == -1 && c != 0x3D) || (dd == -1 && d !=0x3D))
            throw new IllegalArgumentException("Invalid character [" + (a & 0xFF) + ", " + (b & 0xFF) + ", " + (c & 0xFF) + ", " + (d & 0xFF) + "]");

        ret[ret_off++] = (byte) (da << 2 | db >>> 4);
        if (c == 0x3D) // ASCII '='
            return 1;
        
        ret[ret_off++] = (byte) (db << 4 | dc >>> 2);
        if (d == 0x3D) // ASCII '='
            return 2;
        
        ret[ret_off++] = (byte) (dc << 6 | dd);
        return 3;
    }
}

