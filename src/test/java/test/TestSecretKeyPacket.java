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
import core.algorithmhandlers.keymaterial.*;
import core.algorithmhandlers.openpgp.util.*;
import org.bouncycastle.jce.provider.*;
import junit.framework.TestCase;
import java.security.*;
import java.io.*;
import java.util.*;
import javax.crypto.*;

/**
 * <p>This test tests the read portion of the secret key packet. It will read a secret key from a file and use
 * it to try and decode a previously created packet (as created by TestSymmetricallyEncryptedDataPacket).</p>
 */
public class TestSecretKeyPacket extends TestCase 
{
	/** Filenames. */
	public final String outputfile = "TestSecretKeyPacket.pgp";
	public final String secretkeyfile = "/testdata/gpg_1_4_6_secring1.gpg";
	public final String publickeyfile = "/testdata/gpg_1_4_6_pubring1.gpg";
	
	/** Algorithm settings */
	public final int SymmetricAlgorithm = 1; // idea
	public final int PKAlgorithm = 1; // rsa enc & sign
	
	/* Literal packet data 1 */
	public final byte format_1 = 't';   
	public final String rawdata_1 = "This is some literal data...";
	public final String filename_1 = "AFilename.dat";
	
	/* Literal packet data 2 */
	public final byte format_2 = 't';
	public final String rawdata_2 = "This is some more literal data";
	public final String filename_2 = "AnotherFilename.dat";
	
	/** <p>Execute the test.</p>
	 * <p>You should implement this method with your test. Return true if the test
	 * was successful, otherwise return false.</p>
	 */
	public boolean doTest()
	{
		boolean allOK = true;
		
		try
		{
			// generate and write demo packet.
			System.out.println("Adding Bouncy Castle JCE provider...");
			Security.addProvider(new BouncyCastleProvider());
			
			// decode public key and generate a public key object
			System.out.println("Extracting someone's public key from "+publickeyfile+"...");
			OpenPGPPacketInputStream tmpin = new OpenPGPPacketInputStream(getClass().getResourceAsStream( publickeyfile ));
			PublicKeyPacket pkp = (PublicKeyPacket)tmpin.readPacket();
			tmpin.close();
			
			RSAAlgorithmParameters keydata = (RSAAlgorithmParameters)pkp.getKeyData();          
			
			//keydata.setN(new BigInteger("9f9c3dd372349d1a03eef90352b1bc761bf53c76cc9a86904ddda0b742a7056c85f0f6df03d9d812cdd8e0c1ca7c93e3295a10eba804a43c0cf46155911d9eaf0d5db59741d8165be5a43d81bbb705236832194003ec448cc25e59520d72e1ecc2ca004268266ed09fcde9a1f700b4fa25aa639dd04ee46aed978b9a0d923665",16));
			//keydata.setE(new BigInteger("010001",16));
			
			PublicKey publickey = keydata.getPublicKey();
			
			System.out.println("MOD: " + keydata.getN().toString(16));
			System.out.println("EXP: " + keydata.getE().toString(16));  
			
			// create session key object
			System.out.println("Generating a session key ("+SymmetricAlgorithmSettings.getCipherText(SymmetricAlgorithm)+")...");
			KeyGenerator k = KeyGenerator.getInstance(SymmetricAlgorithmSettings.getCipherText(SymmetricAlgorithm), "BC");
			k.init(SecureRandom.getInstance("SHA1PRNG"));
			Key key = k.generateKey();
			
			SessionKey sk = new SessionKey(SymmetricAlgorithm, key.getEncoded());
			System.out.print("SESSIONKEY: ");
			byte [] skdat = sk.getSessionKey();
			for (int i = 0; i<skdat.length; i++) {
			    System.out.print(String.valueOf(skdat[i] & 0xff) + ",");
			}
			System.out.println();
			System.out.println("LENGTH: " + skdat.length);
	
			// create session key packet
			System.out.println("Creating new Public Key Encrypted Session Key Packet...");
			//PublicKeyEncryptedSessionKeyPacket pkeskp = new PublicKeyEncryptedSessionKeyPacket(publickey,sp.getKeyID(),PKAlgorithm,sk);         
			byte kid[] = new byte[8];
			kid[0] = (byte)0xe8;
			kid[1] = (byte)0x31;
			kid[2] = (byte)0x7d;
			kid[3] = (byte)0x43;
			kid[4] = (byte)0x30;
			kid[5] = (byte)0xde;
			kid[6] = (byte)0xf1;
			kid[7] = (byte)0xa0;
			PublicKeyEncryptedSessionKeyPacket pkeskp = new PublicKeyEncryptedSessionKeyPacket(publickey,kid,PKAlgorithm,sk); 		
			
			// Generate data packet
			System.out.println("Creating new Symmetrically Encrypted Data packet...");
			SymmetricallyEncryptedDataPacket sedp = new SymmetricallyEncryptedDataPacket();
			
			System.out.println("Creating and adding first literal packet...");
			LiteralDataPacket p1 = new LiteralDataPacket(format_1, filename_1,  rawdata_1.getBytes());
			
			System.out.println("Creating and adding second literal packet...");
			LiteralDataPacket p2 = new LiteralDataPacket(format_2, filename_2,  rawdata_2.getBytes());
			
			System.out.println("Adding packets...");
			sedp.add(p1);
			sedp.add(p2);
			
			System.out.println("Encrypting...");
			sedp.encryptAndEncode(sk);
			
			// write it out
			System.out.println("Writing packets to file...");
			System.out.println("  Opening packet stream to "+outputfile+"...");
			OpenPGPPacketOutputStream stream = new OpenPGPPacketOutputStream(new FileOutputStream(outputfile));
			
			System.out.println("  Writing sessionkey packet...");
			stream.writePacket(pkeskp);
			System.out.println("  Writing data packet...");
			stream.writePacket(sedp);
			
			System.out.println("  Closing stream...");
			stream.close();
	
	
	
			// Read in secret key
			System.out.println("Reading in Private Key from ("+secretkeyfile+")...");
			OpenPGPPacketInputStream tmpin2 = new OpenPGPPacketInputStream(getClass().getResourceAsStream( secretkeyfile ));
			SecretKeyPacket skp = (SecretKeyPacket)tmpin2.readPacket();
			tmpin2.close();
	
			// decrypt using passphrase
			System.out.println("Decrypting Secret Key...");
			byte [] pass = {'t','e','s','t'};
			skp.decryptKeyData(pass);//"test".getBytes("UTF-8"));
	
	
			// display private and public components
			RSAAlgorithmParameters keydata2 = (RSAAlgorithmParameters)skp.getKeyData();
			
			System.out.println("Public ---------");
			System.out.println("MOD: " + keydata2.getN().toString(16));
			System.out.println("EXP: " + keydata2.getE().toString(16));  
			
			System.out.println("Private --------");
			System.out.println("EXP: " + keydata2.getD().toString(16)); 
			System.out.println("EXP Length: " + keydata2.getD().bitLength()); 
			System.out.println("PRI: " + keydata2.getP().toString(16));
			System.out.println("PRI Length: " + keydata2.getP().bitLength()); 
			System.out.println("PRI2: " + keydata2.getQ().toString(16));
			System.out.println("PRI2 Length: " + keydata2.getQ().bitLength()); 
			System.out.println("MUI: " + keydata2.getU().toString(16));
			System.out.println("MUI Length: " + keydata2.getU().bitLength()); 
	
			// read it in
			System.out.println("Reading packets from file...");
			System.out.println("  Opening packet stream to "+outputfile+"...");
			OpenPGPPacketInputStream instream = new OpenPGPPacketInputStream(new FileInputStream(outputfile));
			
			System.out.println("  Reading Session key packet (and discarding)...");
			PublicKeyEncryptedSessionKeyPacket r_skp = (PublicKeyEncryptedSessionKeyPacket)instream.readPacket();
			
			System.out.println("  Reading Data packet ...");
			SymmetricallyEncryptedDataPacket r_p = (SymmetricallyEncryptedDataPacket)instream.readPacket();
			
			System.out.println("  Closing stream...");
			instream.close();
	
	        // Generate private key
			System.out.println("Generating private key from key data...");
			PrivateKey privatekey = keydata2.getPrivateKey();
	
	        // Decode session key
	        System.out.println("Decrypting session key...");
	        SessionKey sk2 = r_skp.getSessionKey(privatekey);
	        System.out.print("SESSIONKEY: ");
	        debug.Debug.hexDump(1,sk2.getSessionKey());
	        //byte [] skdat2 = sk2.getSessionKey();
	        //for (int i = 0; i<skdat2.length; i++) {
	        //    System.out.print(String.valueOf(skdat2[i] & 0xff) + ",");
	        //}
	        //System.out.println();
	        //System.out.println("LENGTH: " + skdat2.length);
	
	        // Decrypt read packet
	        System.out.println("Decrypting data...");
	            r_p.decryptAndDecode(sk);
	
			// compare.
			// compare packet 1
			System.out.println("Comparing packet 1...");
	
			LiteralDataPacket lp1 = (LiteralDataPacket)r_p.unpack(0);
			
			// format
			System.out.print("  Format... ");
			if (lp1.getFormat()==format_1) {
			    // ok
			    System.out.println("Ok");
			} else {
			    // error
			    System.out.print(lp1.getFormat());
			    System.out.println("...Error!");
			    allOK = false;
			}
			
			// Filename
			System.out.print("  Filename... ");
			if (lp1.getFilename().compareTo(filename_1)==0) {
			    // ok
			    System.out.println("Ok");
			} else {
			    // error
			    System.out.print(lp1.getFilename());
			    System.out.println("Error!");
			    allOK = false;
			}
			
			// data only
			System.out.print("  Data... ");
			if (new String(lp1.getData()).compareTo(rawdata_1)==0) {
			    // ok
			    System.out.println("Ok");
			} else {
			    // error
			    System.out.println("Error!");
			    allOK = false;
			}
			
			// Date
			System.out.print("  Date is... ");
			System.out.println(new Date(lp1.getModDate()*1000).toString());
	
	
	        // compare packet 2
	        System.out.println("Comparing packet 2...");
	
			LiteralDataPacket lp2 = (LiteralDataPacket)r_p.unpack(1);
			
			// format
			System.out.print("  Format... ");
			if (lp2.getFormat()==format_2) {
			    // ok
			    System.out.println("Ok");
			} else {
			    // error
			    System.out.print(lp2.getFormat());
			    System.out.println("...Error!");
			    allOK = false;
			}
			
			// Filename
			System.out.print("  Filename... ");
			if (lp2.getFilename().compareTo(filename_2)==0) {
			    // ok
			    System.out.println("Ok");
			} else {
			    // error
			    System.out.print(lp2.getFilename());
			    System.out.println("Error!");
			    allOK = false;
			}
			
			// data only
			System.out.print("  Data... ");
			if (new String(lp2.getData()).compareTo(rawdata_2)==0) {
			    // ok
			    System.out.println("Ok");
			} else {
			    // error
			    System.out.println(new String(lp2.getData()));
			    System.out.println("Error!");
			    allOK = false;
			}
			
			// Date
			System.out.print("  Date is... ");
			System.out.println(new Date(lp2.getModDate()*1000).toString());
		}
		catch( Exception e )
		{
			e.printStackTrace();
			allOK = false;
		}
		
		// if we got this far then the test should have gone ok
		return allOK;
    }
	
	public void testSecretKeyPacket()
	{
		assertTrue( doTest() );
	}
    
}
