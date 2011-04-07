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

import java.security.*;
import java.math.BigInteger;
import org.bouncycastle.jce.provider.*;
import junit.framework.TestCase;
import core.algorithmhandlers.openpgp.*;
import core.algorithmhandlers.openpgp.util.*;
import core.algorithmhandlers.openpgp.packets.*;
import core.algorithmhandlers.keymaterial.*;
import java.io.*;

/**
* <p>This test creates a pgp file containing a V3 signature packet and a text file containing literal data.</p>
 * <p>The test will sign the packet with a private key, and then attempt to verify it, first against the 
 * wrong public key, then the correct one.</p>
 * <p>To ensure that the signature packet is of a compatible format you should still attempt to verify
 * it using a third party PGP implementation.</p>
 */
public class TestV3Signature extends TestCase {
    
    /* Filenames. */
    public final String datafile = "TestV3Signature.dat";
    public final String sigfile = "TestV3Signature.dat.sig";
    public final String secretkeyfile = "/testdata/gpg_1_4_6_secring1.gpg";
    public final String publickeyfile = "/testdata/gpg_1_4_6_pubring2.gpg";
    
    /* Literal packet data 1 */ 
    public final String rawdata = "This is some data that will be signed...";
    
	/**
	 * setUp() is called before each test case method runs.
	 */
	protected void setUp()
	{
		//debug.Debug.setLevel( 9 );
	}
    
    /** <p>Execute the test.</p>
     * <p>You should implement this method with your test. Return true if the test
     * was successful, otherwise return false.</p>
     * @throws Exception if something went wrong.
     */
    public boolean doTest( int signatureAlgorithm, int hashAlgorithm )
    {
		boolean allOK = true;
        
		try
		{
			// generate and write demo packet.
			System.out.println("Adding Bouncy Castle JCE provider...");
			Security.addProvider(new BouncyCastleProvider());
	
			// extract public & secret key
			System.out.println("Reading signer's Public/Private keypair from ("+secretkeyfile+")...");
			OpenPGPPacketInputStream tmpin2 = new OpenPGPPacketInputStream(getClass().getResourceAsStream( secretkeyfile ));
			SecretKeyPacket skp = (SecretKeyPacket)tmpin2.readPacket();
			tmpin2.close();
	
			// decrypt using passphrase
			System.out.println("Decrypting secret key portion...");
			byte [] pass = {'t','e','s','t'};
			skp.decryptKeyData(pass);
	
			// output some debug info    
			RSAAlgorithmParameters keydata = (RSAAlgorithmParameters)skp.getKeyData();
			debug.Debug.println(1,"Public ---------");
			debug.Debug.println(1,"MOD: "); debug.Debug.hexDump(1,keydata.getN().toByteArray());
			debug.Debug.println(1,"EXP: "); debug.Debug.hexDump(1,keydata.getE().toByteArray());  
			
			debug.Debug.println(1,"Private --------");
			debug.Debug.println(1,"EXP: "); debug.Debug.hexDump(1,keydata.getD().toByteArray()); 
			debug.Debug.println(1,"EXP Length: " + keydata.getD().bitLength()); 
			debug.Debug.println(1,"PRI: "); debug.Debug.hexDump(1,keydata.getP().toByteArray());
			debug.Debug.println(1,"PRI Length: " + keydata.getP().bitLength()); 
			debug.Debug.println(1,"PRI2: " ); debug.Debug.hexDump(1,keydata.getQ().toByteArray());
			debug.Debug.println(1,"PRI2 Length: " + keydata.getQ().bitLength()); 
			debug.Debug.println(1,"MUI: "); debug.Debug.hexDump(1,keydata.getU().toByteArray());
			debug.Debug.println(1,"MUI Length: " + keydata.getU().bitLength());
			
			// extract second public key
			System.out.println("Extracting bogus public key from "+publickeyfile+"...");
			OpenPGPPacketInputStream tmpin = new OpenPGPPacketInputStream(getClass().getResourceAsStream( publickeyfile ));
			PublicKeyPacket pkp = (PublicKeyPacket)tmpin.readPacket();
			tmpin.close();
	
			// construct signature
			System.out.println("Signing...");
			SignaturePacket sp = new SignaturePacket(new V3SignatureMaterial(
				skp.getKeyData().getPrivateKey(),
				skp.getKeyID(),
				0x00,
				signatureAlgorithm,
				hashAlgorithm,
				rawdata.getBytes()
			));
			
			debug.Debug.println(1,"Signature -------");
			debug.Debug.println(1,"Version : " + Integer.toString(sp.getVersion()));
			debug.Debug.println(1,"KeyID : ");
			debug.Debug.hexDump(1, sp.getKeyID());
			debug.Debug.println(1,"Signature material : ");
			debug.Debug.hexDump(1, sp.getSignatureData().getSignature());
			debug.Debug.println(1, "Length : " + Integer.toString(sp.getSignatureData().getSignature().length));
	
			// Save data file
			System.out.println("Saving raw data to "+datafile+"...");
			FileOutputStream out1 = new FileOutputStream(datafile);
			out1.write(rawdata.getBytes()); 
			out1.close();
			
			// Save sig file
			System.out.println("Saving signature to "+sigfile+"...");
			OpenPGPPacketOutputStream out2 = new OpenPGPPacketOutputStream(new FileOutputStream(sigfile));
			out2.writePacket(sp);
			out2.close();
			
			// Read file
			System.out.println("Reading raw data from "+datafile+"...");
			FileInputStream in1 = new FileInputStream(datafile);
			byte rawdata2[] = new byte[in1.available()];
			in1.read(rawdata2);
			in1.close();
			        
			System.out.println("Reading signature from "+sigfile+"...");
			OpenPGPPacketInputStream in2 = new OpenPGPPacketInputStream(new FileInputStream(sigfile));
			SignaturePacket sp2 = (SignaturePacket)in2.readPacket();
			in2.close();
			
			// output some debug info 
			debug.Debug.println(1,"Signature -------");
			debug.Debug.println(1,"Version : " + Integer.toString(sp2.getVersion()));
			debug.Debug.println(1,"KeyID : ");
			debug.Debug.hexDump(1, sp2.getKeyID());
			debug.Debug.println(1,"Signature material : ");
			debug.Debug.hexDump(1, sp2.getSignatureData().getSignature());
			debug.Debug.println(1, "Length : " + Integer.toString(sp2.getSignatureData().getSignature().length));
			debug.Debug.println(1, new BigInteger(sp2.getSignatureData().getSignature()).toString(16));
			debug.Debug.println(1, "Bigint Bitlength : " + Integer.toString(new BigInteger(sp2.getSignatureData().getSignature()).toByteArray().length));
	
			// verifying
			System.out.println( "Verifying message..." );
			System.out.print( "Using wrong key (should fail)..." );
	
			if( !sp2.verify( pkp.getKeyData().getPublicKey(), rawdata2 ) )
			{
				System.out.println( "failed...Ok." );
			}
			else
			{
				System.out.println( "succeeded?!?...ERROR!" );
				allOK = false;
			}
	
			System.out.print( "Using the correct key..." );
	
			if( sp2.verify( skp.getKeyData().getPublicKey(), rawdata2 ) )
			{
				System.out.println( "Ok." );
			}
			else
			{
				System.out.println( "ERROR!" );
				allOK = false;
			}
    	}
		catch( Exception e )
		{
			e.printStackTrace();
			allOK = false;
		}
     
		return allOK;
    }
    
    public void testV3SignatureWithRSAAndMD5()
    {
    	assertTrue( doTest( PublicKeyAlgorithmSettings.RSA_ENCRYPTSIGN, HashAlgorithmSettings.MD5 ) );
    }
    
}
