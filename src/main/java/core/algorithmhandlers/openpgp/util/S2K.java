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
import java.lang.Exception;
import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;

/**
 * <p>This class contains utility methods for generation and conversion of S2K specifiers.</p>
 */
public class S2K {
    
    /** Mode: Simple, Salted, ISalted.*/
    private int mode;
    /** Hash algorithm */
    private int hashalg;
    /** The Salt. */
    private byte salt[];
    /** ISalt octetcount. */
    private int octetcount;
    
    /** Creates a new instance of S2K by parsing an input stream. 
     * @throws AlgorithmException if there was a problem
     */
    public S2K(InputStream in) throws AlgorithmException {
        parse(in);
    }
    
    /** Creates a new instance of S2K by parsing a byte array .
     * @throws AlgorithmException if there was a problem
     */
    public S2K(byte data[]) throws AlgorithmException {
        ByteArrayInputStream in = new ByteArrayInputStream(data);
        parse(in);
    }
    
    /** Produce a SimpleS2K. 
     * @param hashalgorithm The hash algorithm being used.
     */
    public S2K(int hashalgorithm) {
        hashalg = hashalgorithm;
        mode = 0x00;
        salt = new byte[0];
        octetcount = 0;
    }
    
    /** Creates a Salted S2K. 
     * @param hashalgorithm The hash algorithm being used.
     * @param saltdata[] The salt data.
     */
    public S2K(int hashalgorithm, byte saltdata[]) {
        hashalg = hashalgorithm;
        mode = 0x01;
        salt = saltdata;
        octetcount = 0;
    }
    
    /** Creates an Iterated Salted S2K. 
     * @param hashalgorithm The hash algorithm being used.
     * @param saltdata[] The salt data.
     * @param count How many octets to hash (in its encoded form).
     */
    public S2K(int hashalgorithm, byte saltdata[], int count) {
        hashalg = hashalgorithm;
        mode = 0x03;
        salt = saltdata;
        octetcount = count;
    }

    /** 
     * Generate a key from a pass phrase.
     * @param passphrase[] The pass phrase to use.
     * @param keyalgorithm The key algorithm (and thus the key size) to generate the key for (IDEA, 3DES etc).
     * @throws AlgorithmException if there was a problem.
     */
    public SecretKey generateKey(byte passphrase[], int keyalgorithm) throws AlgorithmException {
    	
        // this is a modified key gen method, using Cryptix and GnuPG as the references.
    	debug.Debug.println(1, "xxx S2K.generateKey(): octetcount = " + octetcount);
    	debug.Debug.println(1, "xxx S2K.generateKey(): hashalg = " + hashalg);
    	debug.Debug.println(1, "xxx S2K.generateKey(): keyalgorithm = " + keyalgorithm);
        
        try {
            // create message digest
            MessageDigest md = MessageDigest.getInstance(HashAlgorithmSettings.getHashText(hashalg), "BC");

            // generate key material from pass phrase 
            int keysize = SymmetricAlgorithmSettings.getDefaultKeySize(keyalgorithm) / 8;
            byte keymaterial[] = new byte[keysize];
            int combinedLength = passphrase.length + salt.length;
            long codedCount = 0;
            if (mode == 0x03) {
            	codedCount = (16L + (octetcount & 15)) << ((octetcount >> 4) + 6);
            }
            int pos = 0;
            
            for (int pass = 0; pos < keysize; ++pass) {
            	if (pass > 0) {
            		md.reset();
                	for (int j = 0; j < pass; j++)
                		md.update((byte)0);
            	}
            	
            	if (mode == 0x01 || mode == 0x03) { // 0x01 = Salted, 0x03 = Iterated and Salted
    				long count = combinedLength;  // mode 0x01 uses the combined length
    				
    				if (mode == 0x03) { // mode 0x03 can iterate
    					count = codedCount;
    					if (count < combinedLength) count = combinedLength;
    					
    					while (count > combinedLength) { // salted iteration
        					md.update(salt);
        					md.update(passphrase);
        					count -= combinedLength;
        				}
    				}
    				
    				// hash the remainder
    				if (count < 8) {
    					for (int j = 0; j < count; ++j) md.update(salt[j]);
    				} else {
    					md.update(salt);
    					count -= 8;
    					for (int j = 0; j < count; ++j) md.update(passphrase[j]);
    				}
    			} else { // mode 0x0, simple S2K
            		md.update(passphrase);
    			}
            	byte[] hash = md.digest();
            	
            	int size = hash.length;
            	if (size + pos > keysize) size = keysize - pos;
            	System.arraycopy(hash, 0, keymaterial, pos, size);
            	pos += size;
            }
            // create appropriate key
            return new SecretKeySpec(keymaterial, SymmetricAlgorithmSettings.getCipherText(keyalgorithm));
        
        } catch (Exception e) {
            throw new AlgorithmException(e.getMessage());
        }
        
    }

    /**
	 * Parse out the S2k data into a PGP file compatible format.
	 * 
	 * @throws AlgorithmException
	 *             if there was a problem
	 */
    public byte[] toByteArray() throws AlgorithmException {
        
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
        
            out.write(mode & 0xFF);
            out.write(hashalg & 0xFF);

            switch (mode) {
                case 0x00 : break; // simple
                case 0x01 : // Salted
                    out.write(salt);
                    break; 
                case 0x03 : // I Salted
                    out.write(salt); // write salt
                    out.write(octetcount & 0xFF); // read count (in its encoded form)
                    break; 
                default : throw new AlgorithmException("S2K Specifier is invalid!");
            }
            
            return out.toByteArray();
            
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
    /**
     * Parse out the S2k Specifier from an input stream.
     * @throws AlgorithmException if there was a problem
     */
    protected void parse(InputStream in) throws AlgorithmException {
        try {
            mode = in.read() & 0xFF; // read in the mode (see RFC2440 3.6)
            hashalg = in.read() & 0xFF; // read in the hash algorithm to use
            
            switch (mode) {
                case 0x00 : 
                    salt = new byte[0]; // no salt data (dirty hack left here from testing)
                    break; // simple
                case 0x01 : // Salted
                    salt = new byte[8]; 
                    in.read(salt);
                    break; 
                case 0x03 : // I Salted
                    // read salt
                    salt = new byte[8]; 
                    in.read(salt);
                    
                    // read count (in its encoded form)
                    octetcount = in.read() & 0xFF;
                    break; 
                default : throw new AlgorithmException("S2K Specifier is invalid!");
            }
            
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
   
}
