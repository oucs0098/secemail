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
import javax.crypto.*;
import java.security.spec.RSAPublicKeySpec;

/**
 * <p>This test will generate a PGP compatible message in ascii armored form, then attempts to read it
 * back in.</p>
 */
public class TestASCIIArmor extends TestCase {
    
    /** Filenames. */
    public final String outputfile = "TestASCIIArmor.pgp";
    public final String publickeyfile = "/testdata/IcewingPublicKey.packet";
    public final String publickeysigfile = "/testdata/IcewingPublicKeySig.packet";
    
    /** Algorithm settings */
    public final int SymmetricAlgorithm = 1; // idea
    public final int PKAlgorithm = 1; // rsa enc & sign
    
    /* Literal packet data 1 */
    public final byte format_1 = 't';   
    public final String rawdata_1 = "This is some literal data";
    public final String filename_1 = "AFilename.dat";
    
    /* Literal packet data 2 */
    public final byte format_2 = 't';
    public final String rawdata_2 = "This is some more literal data";
    public final String filename_2 = "AnotherFilename.dat";
    
	/** <p>Execute the test.</p>
	 * <p>You should implement this method with your test. Return true if the test
	 * was successful, otherwise return false.</p>
	 */
	public void testASCIIArmor()
	{
		boolean allOK = true;
		
		System.out.println("Adding Bouncy Castle JCE provider...");
		Security.addProvider(new BouncyCastleProvider());

		try
		{
			// Extract signature
			System.out.println("Extracting public key signature from "+publickeysigfile+"...");
			OpenPGPPacketInputStream sigin = new OpenPGPPacketInputStream(getClass().getResourceAsStream( publickeysigfile ));
			SignaturePacket sp = (SignaturePacket)sigin.readPacket();
			sigin.close();
	
			// decode public key and generate a public key object
			System.out.println("Extracting someone's public key from "+publickeyfile+"...");
			OpenPGPPacketInputStream tmpin = new OpenPGPPacketInputStream(getClass().getResourceAsStream( publickeyfile ));
			PublicKeyPacket pkp = (PublicKeyPacket)tmpin.readPacket();
			tmpin.close();
			
			RSAAlgorithmParameters keydata = (RSAAlgorithmParameters)pkp.getKeyData();
			
			RSAPublicKeySpec publickeyspec = new RSAPublicKeySpec(keydata.getN(), keydata.getE());
			KeyFactory keyFactory = KeyFactory.getInstance(PublicKeyAlgorithmSettings.getCipherText(PKAlgorithm));
			PublicKey publickey = keyFactory.generatePublic(publickeyspec);                
	
			// create session key object
			System.out.println("Generating a session key...");
			KeyGenerator k = KeyGenerator.getInstance(SymmetricAlgorithmSettings.getCipherText(SymmetricAlgorithm), "BC");
			k.init(SecureRandom.getInstance("SHA1PRNG"));
			Key key = k.generateKey();
			
			SessionKey sk = new SessionKey(SymmetricAlgorithm, key.getEncoded());
			//byte [] skdat = sk.getSessionKey();
	
			// create session key packet
			System.out.println("Creating new Public Key Encrypted Session Key Packet...");
			PublicKeyEncryptedSessionKeyPacket pkeskp = new PublicKeyEncryptedSessionKeyPacket(publickey,sp.getKeyID(),PKAlgorithm,sk);
	
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
	
			// Armor
			System.out.println("Generating ASCII Armor...");    
			ByteArrayOutputStream raw = new ByteArrayOutputStream();
			
			System.out.println("  Opening packet stream...");
			OpenPGPPacketOutputStream stream = new OpenPGPPacketOutputStream(raw);
			
			System.out.println("  Writing sessionkey packet...");
			stream.writePacket(pkeskp);
			System.out.println("  Writing data packet...");
			stream.writePacket(sedp);
			
			System.out.println("  Closing stream...");
			stream.close();
			
			System.out.println("  Generating armor...");
			String ascii = Armory.armor(raw.toByteArray());
	
			// write it out
			System.out.println("Writing armored message to file...");
			System.out.println("  Opening "+outputfile+"...");
			
			File f = new File(outputfile);
			f.delete();
			f.createNewFile();
			BufferedWriter outputStream = new BufferedWriter(new FileWriter(f));
			
			System.out.println("  Writing header...");
			outputStream.write("-----BEGIN PGP MESSAGE-----");
			outputStream.newLine();
			outputStream.newLine();
			
			System.out.println("  Writing message...");
			outputStream.write(ascii);
			outputStream.newLine();
			
			System.out.println("  Writing footer...");
			outputStream.write("-----END PGP MESSAGE-----");
			outputStream.newLine();
			
			System.out.println("  Closing file...");
			outputStream.flush();
			outputStream.close();
		}
		catch( Exception e )
		{
			e.printStackTrace();
			allOK = false;
		}
            
        // TODO: Read in and test.
		
        // if we got this far then the test should have gone ok
        assertTrue( allOK );
    }
    
}
