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
 * <p>This is an iterative test to debug a problem with the PGP CFB mode cipher
 * where the decryption will fail for data of certain lengths.</p>
 */
public class TestPGPCFB extends TestCase
{
    
	protected byte[] encrypt( Key key, byte[] data, int skalgorithm )
			throws Exception
	{
		int blockSize = SymmetricAlgorithmSettings
				.getDefaultBlockSize( skalgorithm ) / 8;
	
		// create IV
		byte[] ivdata = new byte[blockSize];
		SecureRandom rnd = SecureRandom.getInstance( "SHA1PRNG" );
		rnd.nextBytes( ivdata );
		IvParameterSpec iv = new IvParameterSpec( ivdata );
	
		// create cipher
		Cipher cipher = Cipher.getInstance( SymmetricAlgorithmSettings
				.getFullCipherText( skalgorithm ), "BC" );
		cipher.init( Cipher.ENCRYPT_MODE, key, iv );
	
		return cipher.doFinal( data );
	}
    
    protected byte[] decrypt( Key key, byte[] data, int skalgorithm ) throws Exception
	{
		//int blockSize = SymmetricAlgorithmSettings
		//		.getDefaultBlockSize( skalgorithm ) / 8;

		// create cipher
		Cipher cipher = Cipher.getInstance( SymmetricAlgorithmSettings
				.getFullCipherText( skalgorithm ), "BC" );
		cipher.init( Cipher.DECRYPT_MODE, key );

		return cipher.doFinal( data );
	}
    
    private boolean doTest( int skalgorithm, int iterations )
    {
    	SecureRandom rnd;
        Key key;
        
        boolean allOK = true; // has every test so far been successful?
        
        try
        {
			// initialising
			System.out.println("Adding Bouncy Castle JCE provider...");
			Security.addProvider(new BouncyCastleProvider());
			
	        System.out.println("Initialising RNG...");
	        rnd = SecureRandom.getInstance("SHA1PRNG");
	
	        System.out.println("Generating key...");
	        KeyGenerator k = KeyGenerator.getInstance(SymmetricAlgorithmSettings.getCipherText(skalgorithm), "BC");
	        k.init(SecureRandom.getInstance("SHA1PRNG"));
	        key = k.generateKey();
	        
	        System.out.println("Executing test, please wait...");
	        
	        for (int n = 0; n < iterations; n++) {
	            
	            // data and result registers
	            boolean success = true; // is this test pass successful
	            int failedat = -1;
	            
	            // execute test and record results
	            try {
	                byte raw[] = new byte[n+1 + (SymmetricAlgorithmSettings.getDefaultBlockSize(skalgorithm)/8)+2];
	                rnd.nextBytes(raw);
	                raw[8] = raw[6]; raw[9] = raw[7]; // two byte repeat data
	                
	                byte enc[] = encrypt(key, raw, skalgorithm);
	                byte dec[] = decrypt(key, enc, skalgorithm);
	                
	                // compare
	                for (int na = 0; na < n+1; na++) {
	                    if (dec[na]!= raw[na]) {
	                        System.out.println("Pass " + n + ": has failed, check trace file for details.");
	                        failedat = na;
	                        success = false;
	                        allOK = false;
	                        break;
	                    }
	                }
	                
	            }
				catch( Exception e )
				{
	                System.out.println(e.getMessage());
	                success = false;
	                allOK = false;
	                
	                throw e;
	            }
	            
	            // write csv stuff
	            System.out.print( "Iteration " + n + " was " );
	            System.out.println( success ? "successful." : "not successful, failing at offset " + failedat + "." );
	        }
        }
        catch( Exception e )
        {
        	e.printStackTrace();
        	allOK = false;
        }
            
        return allOK;
    }
    
    public void testPGPCFBWithIDEA()
    {
    	assertTrue( doTest( SymmetricAlgorithmSettings.IDEA, 25 ) );
    }
    
    public void testPGPCFBWithCAST5()
    {
    	assertTrue( doTest( SymmetricAlgorithmSettings.CAST5, 25 ) );
    }
    
    public void testPGPCFBWith3DES()
    {
    	assertTrue( doTest( SymmetricAlgorithmSettings.TRIPLEDES, 25 ) );
    }
    
}
