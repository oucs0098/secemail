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

import core.algorithmhandlers.openpgp.*;
import core.algorithmhandlers.openpgp.packets.*;
import core.algorithmhandlers.openpgp.util.*;
import org.bouncycastle.jce.provider.*;
import junit.framework.TestCase;
import java.security.*;
import java.io.*;
import javax.crypto.*;


/**
 * <p>This test generates a random RSA keypair, writes them as an MPI and reads them back in.</p>
 * <p>This is done a number of times. If the bug is present, the RSA cipher will throw an exception
 * with the value "attempt to process message to long for cipher"
 */
public class TestMPIBug extends TestCase 
{
    
	/** <p>Execute the test.</p>
	 * <p>You should implement this method with your test. Return true if the test
	 * was successful, otherwise return false.</p>
	 */
	public boolean doTest( int iterations, int symmetricAlgorithm, int pkAlgorithm )
	{
		boolean allOK = true;
		
		try
		{
			System.out.println("Adding Bouncy Castle JCE provider...");
			Security.addProvider(new BouncyCastleProvider());
	
			for( int n = 0; n < iterations; n++ )
			{
				System.out.println("Running test "+n+"...");
				
				// generate key pair
				KeyPairGenerator k = KeyPairGenerator.getInstance(PublicKeyAlgorithmSettings.getCipherText(pkAlgorithm), "BC");
				k.initialize(PublicKeyAlgorithmSettings.getDefaultKeySize(pkAlgorithm), SecureRandom.getInstance("SHA1PRNG"));
				
				KeyPair kp = k.generateKeyPair();
				
				// generate session key
				KeyGenerator k2 = KeyGenerator.getInstance(SymmetricAlgorithmSettings.getCipherText(symmetricAlgorithm), "BC");
				k2.init(SecureRandom.getInstance("SHA1PRNG"));
				Key key = k2.generateKey();
				
				SessionKey sk = new SessionKey(symmetricAlgorithm, key.getEncoded());
				
				// encrypt session key
				byte keyid[] = new byte[8];
				for (int na = 0; na<keyid.length; na++) keyid[na] = 0x00;
				
				PublicKeyEncryptedSessionKeyPacket pkeskp = new PublicKeyEncryptedSessionKeyPacket(kp.getPublic(),keyid,pkAlgorithm,sk);
				
				
				// write session key
				ByteArrayOutputStream out = new ByteArrayOutputStream();
				OpenPGPPacketOutputStream outstream = new OpenPGPPacketOutputStream(out);
				outstream.writePacket(pkeskp);
				outstream.close();
				
				// read session key
				ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
				OpenPGPPacketInputStream instream = new OpenPGPPacketInputStream(in);
				
				PublicKeyEncryptedSessionKeyPacket pkeskp2 = (PublicKeyEncryptedSessionKeyPacket)instream.readPacket();
				
				// compare
				SessionKey sk2 = pkeskp2.getSessionKey(kp.getPrivate());
				if (sk.getAlgorithm()!=sk2.getAlgorithm()) 
					throw new Exception("Algorithm codes are different!");
				if (sk.getSessionKey().length != sk2.getSessionKey().length)
					throw new Exception("Session key lengths are different!");
				
				byte[] rawsk1 = sk.getSessionKey();
				byte[] rawsk2 = sk2.getSessionKey();
				for (int na = 0; na<sk.getSessionKey().length; na++)
					if (rawsk1[na]!=rawsk2[na]) throw new Exception("Session keys are different!");
	        }
		}
		catch( Exception e )
		{
			e.printStackTrace();
			allOK = false;
		}
            
        return allOK;
    }
	
	public void testMPIBugWithIDEAAndRSA()
	{
		assertTrue( doTest( 50, SymmetricAlgorithmSettings.IDEA, PublicKeyAlgorithmSettings.RSA_ENCRYPTSIGN ) );
	}
    
}
