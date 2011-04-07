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
import junit.framework.TestCase;
import java.security.*;
import java.math.BigInteger;

/**
 * <p>A test app to better diagnose exactly what is going wrong with the MPI class.</p>
 */
public class TestMPIBug2 extends TestCase {
    
	/** <p>Execute the test.</p>
	 * <p>You should implement this method with your test. Return true if the test
	 * was successful, otherwise return false.</p>
	 */
	private boolean doTest()
	{
		boolean allOK = true;
		
		try
		{
			for (int n = 0; n < 50; n++) {
				System.out.println("Test "+n+": ");
				BigInteger x = new BigInteger(64, SecureRandom.getInstance("SHA1PRNG"));
				BigInteger y = MPI.valueOf(MPI.toByteArray(x));
				
				System.out.println("X: "+x.toString(16));
				System.out.println("Y: "+y.toString(16));

			    if ((x.compareTo(y)!=0) || 
					(x.bitLength()!=y.bitLength()) || 
					(x.bitCount()!=y.bitCount()) ||
					(x.equals(y)!=true))
				{
			    	allOK = false;
			    	break;
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
	
	public void testMPIBug2()
	{
		assertTrue( doTest() );
	}
    
}
