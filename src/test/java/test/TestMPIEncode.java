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

import core.algorithmhandlers.keymaterial.*;
import junit.framework.TestCase;
import java.math.BigInteger;
import java.io.*;
import java.security.*;

/**
 * <p>This test simply creates a bogus RSAAlgorithParameters object, provides some values, trys to write them
 * out, reads them back in and compares the values.</p>
 */
public class TestMPIEncode extends TestCase 
{

	/** <p>Execute the test.</p>
	 * <p>You should implement this method with your test. Return true if the test
	 * was successful, otherwise return false.</p>
	 */
	public boolean doTest()
	{
		try
	    {
			System.out.println("Creating RSAAlgorithmParameter object with bogus values...");
			BigInteger n = new BigInteger(64, SecureRandom.getInstance("SHA1PRNG"));
			BigInteger e = new BigInteger(64, SecureRandom.getInstance("SHA1PRNG"));
			RSAAlgorithmParameters rsa = new RSAAlgorithmParameters();
			rsa.setN(n);
			rsa.setE(e);
			
			// write out
			System.out.println("Encoding to stream...");
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			out.write(rsa.encodePublicKeyComponents());
			
			// read in 
			System.out.println("Decoding from stream...");
			ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
			RSAAlgorithmParameters rsa2 = new RSAAlgorithmParameters();
			rsa2.decodePublicKeyComponents(in);
			
			// compare
			System.out.print("Comparing N with stored value...");
			if (rsa2.getN().compareTo(n)==0) {
				System.out.println("Ok");
			} else {
				System.out.println("Error");
				return false;
			}
			
			System.out.print("Comparing E with stored value...");
			if (rsa2.getE().compareTo(e)==0) {
				System.out.println("Ok");
			} else {
				System.out.println("Error");
				return false;
			}
		}
	    catch( Exception e )
	    {
	    	e.printStackTrace();
	    	return false;
	    }
		    
		return true;
    }
	
	public void testMPIEncode()
	{
		assertTrue( doTest() );
	}
    
}
