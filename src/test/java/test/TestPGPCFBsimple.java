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
 * Test the CFB mode used for secret key material and symmetrically encrypted session key packets.
 */
public class TestPGPCFBsimple extends TestCase {
    
	public final int hashalgorithm = HashAlgorithmSettings.SHA1;
    private byte[] IV;
    
    protected byte[] encrypt(Key key, byte[] data, int skAlgorithm) throws Exception 
    {
        // create cipher
        Cipher cipher = Cipher.getInstance(SymmetricAlgorithmSettings.getCipherText(skAlgorithm) + "/PGPCFB/" + SymmetricAlgorithmSettings.getPaddingText(skAlgorithm),"BC");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        IV = cipher.getIV();
        
        return cipher.doFinal(data);  
    }
    
    protected byte[] decrypt(Key key, byte[] data, int skAlgorithm) throws Exception 
    {
        IvParameterSpec iv = new IvParameterSpec(IV); 
        
        // create cipher
        Cipher cipher = Cipher.getInstance(SymmetricAlgorithmSettings.getCipherText(skAlgorithm) + "/PGPCFB/" + SymmetricAlgorithmSettings.getPaddingText(skAlgorithm),"BC");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        return cipher.doFinal(data);
    }
    
	/** <p>Execute the test.</p>
	 * <p>You should implement this method with your test. Return true if the test
	 * was successful, otherwise return false.</p>
	 */
	public boolean doTest( int skAlgorithm, int iterations )
	{
		SecureRandom rnd;
		Key key;
		
		boolean allOK = true; // keeps track of the overall test success
		
		try
		{
			System.out.println("Adding Bouncy Castle JCE provider...");
			Security.addProvider(new BouncyCastleProvider());
			
			System.out.println("Initialising RNG...");
			rnd = SecureRandom.getInstance("SHA1PRNG");
			
			System.out.println("Generating key...");
			KeyGenerator k = KeyGenerator.getInstance(SymmetricAlgorithmSettings.getCipherText(skAlgorithm), "BC");
			k.init(SecureRandom.getInstance("SHA1PRNG"));
			key = k.generateKey();
	        
	        System.out.println("Executing test, please wait...");
	        
	        
	        for (int n = 0; n < iterations; n++) 
	        {
	            // execute test and record results
	            try {
	                byte raw[] = new byte[n+1];
	                rnd.nextBytes(raw);
	                
	                byte enc[] = encrypt(key, raw, skAlgorithm);
	                byte dec[] = decrypt(key, enc, skAlgorithm);
	                
	                // compare
	                for (int na = 0; na < n+1; na++) {
	                    if (dec[na]!= raw[na]) {
	                        System.out.println("Pass " + n + ": has failed, check trace file for details.");
	                        allOK = false;
	                        break;
	                    }
	                }
	                
	            } catch (Exception e) {
	                System.out.println(e.getMessage());
	                allOK = false;
	                
	                throw e;
	            }
	        }
		}
		catch( Exception e )
		{
			e.printStackTrace();
			allOK = false;
		}

        return allOK;
    }
	
	public void testPGPCFBSimpleWithIDEA()
    {
    	assertTrue( doTest( SymmetricAlgorithmSettings.IDEA, 25 ) );
    }
    
    public void testPGPCFBSimpleWithCAST5()
    {
    	assertTrue( doTest( SymmetricAlgorithmSettings.CAST5, 25 ) );
    }
    
    public void testPGPCFBSimpleWith3DES()
    {
    	assertTrue( doTest( SymmetricAlgorithmSettings.TRIPLEDES, 25 ) );
    }
    
}
