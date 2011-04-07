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

package core.algorithmhandlers.openpgp.util;
import core.exceptions.AlgorithmException;
import java.lang.String;

/**
 * <p>A class that returns settings for the hash algorithm, translating the algorithm
 * code into a symmetric cipher.</p>
 */
public class HashAlgorithmSettings {
    
    public static final int MD5 = 1;
    public static final int SHA1 = 2;
    public static final int RIPEMD160 = 3;
    public static final int SHA256 = 8;
    public static final int SHA384 = 9;
    public static final int SHA512 = 10;
    public static final int SHA224 = 11;
 
    /** <p>A method that returns a correctly formatted hash text string for creating a 
     * JCE message digest.</p>
     * @throws AlgorithmException if the requested algorithm is not supported.
     */
    public static String getHashText(int algorithm) throws AlgorithmException {
        switch (algorithm) {
            case MD5 : return "MD5"; 
            case SHA1 : return "SHA1"; 
            case RIPEMD160 : return "RIPEMD160";
            case SHA256 : return "SHA256";
            case SHA384 : return "SHA384";
            case SHA512 : return "SHA512";
            case SHA224 : return "SHA224";
            default : throw new AlgorithmException("Requested hash algorithm (" + 
            		algorithm + ") not supported.");
        }
    }
    
    /** <p>A method that returns the message digest size, in bytes, for a given algorithm
     * code.</p>
     * @throws AlgorithmException if the requested algorithm is not supported.
     */
    public static int getDigestSize(int algorithm) throws AlgorithmException {
        switch (algorithm) {
            case MD5 : return 16; 
            case SHA1 : return 20; 
            case RIPEMD160 : return 20;
            case SHA256 : return 32;
            case SHA384 : return 48;
            case SHA512 : return 64;
            case SHA224 : return 28;
            default : throw new AlgorithmException("Requested hash algorithm (" + 
            		algorithm + ") not supported.");
        }
    }
}
