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

import org.bouncycastle.jce.provider.*;
import junit.framework.TestCase;
import java.io.*;
import java.security.*;
import javax.crypto.*;

/**
 * <p>This is a quick and dirty stand alone test to try and get Bouncy castle to create and use an IDEA cipher.</p>
 * <p>I have been having real problems with encryption and decryption in PGP, hopefully i can get it workign in this simplified senario.</p>
 * <p>I have no idea whether idea can be used in the correct mode to be compatible with PGP... i guess i'll cross that bridge when i come to it.</p>
 */
public class TestIDEA extends TestCase {
    
    public final String data = "This is some data that i hope to be able to encrypt.";
    public final String algorithm = "IDEA";
    public final String params = "/CFB64/NoPadding";//"/CBC/ISO10126Padding";
    
    /** <p>Execute the test.</p>
     * <p>You should implement this method with your test. Return true if the test
     * was successful, otherwise return false.</p>
     */
    public void testIDEA()
    {
        boolean allOK = true;
		Cipher cipher = null;
		Cipher cipher2 = null;
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		
		try
		{
			System.out.print("Adding BouncyCastleProvider...");    
			Security.addProvider(new BouncyCastleProvider());
			System.out.println("Ok.");
			
			System.out.print("Generating a random session key...");
			KeyGenerator k = KeyGenerator.getInstance(algorithm, "BC");
			
			//SecretKeyFactory kf = SecretKeyFactory.getInstance("CAST5", "BC");
			//SecretKey keeeey = new SecretKeySpec("rawdata".getBytes(),"IDEA");
			
			k.init(SecureRandom.getInstance("SHA1PRNG"));
			Key key = k.generateKey();
			System.out.println("Ok.");
			
			System.out.print("Encrypting data ("+algorithm+params+")...");
			cipher = Cipher.getInstance(algorithm + params,"BC");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			CipherOutputStream cOut = new CipherOutputStream(buffer, cipher);
			cOut.write(data.getBytes());
			cOut.close();
			System.out.println("Ok.");
			
			System.out.print("Decrypting data...");   
			ByteArrayOutputStream buffer2 = new ByteArrayOutputStream();
			cipher2 = Cipher.getInstance(algorithm + params, "BC");
			AlgorithmParameters params = AlgorithmParameters.getInstance(algorithm,"BC");
			params.init(cipher.getIV());
			cipher2.init(Cipher.DECRYPT_MODE, key, params);
			CipherInputStream cIn = new CipherInputStream(new ByteArrayInputStream(buffer.toByteArray()), cipher2);
			
			int b;
			while( ( b = cIn.read() ) != -1 )
				buffer2.write( b );
			System.out.println( "Ok." );
	
			System.out.print( "Comparing..." );
			if( new String( buffer2.toByteArray() ).compareTo( data ) != 0 )
			{
				System.out.println( "Error!" );
				System.out.println( "Data returned was : "
						+ new String( buffer2.toByteArray() ) );
				allOK = false;
			}
			else
			{
				System.out.println( "Ok" );
				System.out.println( "Data returned was : "
						+ new String( buffer2.toByteArray() ) );
			}
		}
		catch( Exception e )
		{
			e.printStackTrace();
			allOK = false;
		}
		
		// Inform JUnit of the result of the test ...
		assertTrue( allOK );
    }
    
}
