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

package test;

import core.algorithmhandlers.openpgp.util.*;
import org.bouncycastle.jce.provider.*;
import junit.framework.TestCase;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * <p>This class tests the S2K key generator.</p>
 * <p>It will attempt to encrypt and decrypt arbitrary data using a key generated from
 * a given passphrase for each possible S2K convention - simple, Salted and Itterated Salted.</p>
 */
public class TestS2K extends TestCase {
    
    public final String passPhrase = "This is the passphrase";
    public final String rawdata = "This is some raw data that will be encrypted, but maybe its a bit bugged and needs some more stuff here......1234567890";
    public final int skalgorithm = 1;
    public final int hashalgorithm = 1;
    
    protected byte[] generateSalt() throws Exception {
      
        System.out.println("  Generating salt...");

        byte salt[] = new byte[8];

        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
        rng.nextBytes(salt);

        return salt;
       
    }
    
    protected byte[] encrypt(Key key, byte[] data) throws Exception {

        System.out.println("  Encrypting using key...");

        int blockSize = SymmetricAlgorithmSettings.getDefaultBlockSize(skalgorithm)/8;

        // create IV
        byte[] ivdata = new byte[blockSize];
        SecureRandom rnd = SecureRandom.getInstance("SHA1PRNG");
        rnd.nextBytes(ivdata);
        IvParameterSpec iv = new IvParameterSpec(ivdata);

        // create cipher
        Cipher cipher = Cipher.getInstance(SymmetricAlgorithmSettings.getFullCipherText(skalgorithm),"BC");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        return cipher.doFinal(data);  
    }
    
    protected byte[] decrypt(Key key, byte[] data) throws Exception {

        System.out.println("  Decrypting using key...");

        // create cipher
        Cipher cipher = Cipher.getInstance(SymmetricAlgorithmSettings.getFullCipherText(skalgorithm),"BC");
        cipher.init(Cipher.DECRYPT_MODE, key);

        return cipher.doFinal(data);
    }
    
    protected void compare(byte dec[]) throws Exception {
        
        System.out.println("  Comparing decrypted data with original...");
        
        if (dec.length!=rawdata.getBytes().length) 
            throw new Exception("Decrypted data is the wrong length!");
        for (int n = 0; n<dec.length; n++) 
            if (dec[n]!=rawdata.getBytes()[n]) 
                throw new Exception("Decrypted data is not the same as original!\n ("
                    + new String(dec) + ")");
    }
    
    protected boolean simple()
    {
        System.out.println("Testing Simple S2K...");
        boolean allOK = true;
        
        try
        {
			S2K s2k1 = new S2K(hashalgorithm);
			Key k1 = s2k1.generateKey(passPhrase.getBytes(), skalgorithm);
			byte enc[] = encrypt(k1, rawdata.getBytes());
			
			S2K s2k2 = new S2K(hashalgorithm);
			Key k2 = s2k2.generateKey(passPhrase.getBytes(), skalgorithm);
			byte dec[] = decrypt(k2, enc);
			
			compare(dec);
        }
        catch( Exception e )
        {
        	e.printStackTrace();
        	allOK = false;
        }
        
        return allOK;
    }
    
    protected boolean salted() 
    {
        System.out.println("Testing Salted S2K...");
        boolean allOK = true;
        
        try
        {
			byte salt[] = generateSalt();
			
			S2K s2k1 = new S2K(hashalgorithm, salt);
			Key k1 = s2k1.generateKey(passPhrase.getBytes(), skalgorithm);
			byte enc[] = encrypt(k1, rawdata.getBytes());
			
			S2K s2k2 = new S2K(hashalgorithm, salt);
			Key k2 = s2k2.generateKey(passPhrase.getBytes(), skalgorithm);
			byte dec[] = decrypt(k2, enc);
			
			compare(dec);
        }
        catch( Exception e )
        {
        	e.printStackTrace();
        	allOK = false;
        }
        
        return allOK;
    }
    
    protected boolean iterated()
    {
        System.out.println("Testing Iterated S2K...");
        boolean allOK = true;
        
        try
        {
			byte salt[] = generateSalt();
			
			S2K s2k1 = new S2K(hashalgorithm, salt, 2);
			Key k1 = s2k1.generateKey(passPhrase.getBytes(), skalgorithm);
			byte enc[] = encrypt(k1, rawdata.getBytes());
			
			S2K s2k2 = new S2K(hashalgorithm, salt, 2);
			Key k2 = s2k2.generateKey(passPhrase.getBytes(), skalgorithm);
			byte dec[] = decrypt(k2, enc);
			
			compare(dec);
        }
        catch( Exception e )
        {
        	e.printStackTrace();
        	allOK = false;
        }
        
        return allOK;
    }
    
	/**
	 * Sets up the test.
	 * Called before every test case method.
	 */
	protected void setUp()
	{
		System.out.println("Adding Bouncy Castle JCE provider...");
        Security.addProvider(new BouncyCastleProvider());
	}
    
	/**
	 * JUnit test case.
	 * Tests the simple S2K (String-to-key) functionality
	 */
	public void testSimpleS2K()
	{
		assertTrue( simple() );
	}
	
	/**
	 * JUnit test case.
	 * Tests the salted S2K (String-to-key) functionality
	 */
	public void testSaltedS2K()
	{
		assertTrue( salted() );
	}
	
	/**
	 * JUnit test case.
	 * Tests the salted and iterated S2K (String-to-key) functionality
	 */
	public void testIteratedS2K()
	{
		assertTrue( iterated() );
	}
    
}
