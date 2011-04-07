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

/**
 * <p>This test will attempt to load and decode a pgp message generated with a third party app.</p>
 */
public class TestPacketDecode extends TestCase {
    
    public final String secretkeyfile = "/testdata/gpg_1_4_6_secring2.gpg";
    public final String datafilename = "/testdata/song.txt.gpg";
    
    /** <p>Execute the test.</p>
     * <p>You should implement this method with your test. Return true if the test
     * was successful, otherwise return false.</p>
     */
    public void testPacketDecode()
    {
        boolean allOK = true;
        debug.Debug.setLevel(3);
        
        try
        {
			System.out.println("Adding Bouncy Castle JCE provider...");
			Security.addProvider(new BouncyCastleProvider());
			
			// extract secret key
			System.out.println("Extract secret key...");
			OpenPGPPacketInputStream keyfile = new OpenPGPPacketInputStream(getClass().getResourceAsStream( secretkeyfile ));
			// skip past the leading packets...
			keyfile.readPacket();  // secret key packet (primary key)
			keyfile.readPacket();  // user id packet
			keyfile.readPacket();  // signature packet
			keyfile.readPacket();  // trust packet
			SecretSubkeyPacket ssp = (SecretSubkeyPacket)keyfile.readPacket();
			keyfile.close();
			
			// Read data file
			System.out.println("Reading data file...");
			OpenPGPPacketInputStream datafile = new OpenPGPPacketInputStream(getClass().getResourceAsStream( datafilename ));
			
			// read session key
			System.out.println("Read session key...");
			PublicKeyEncryptedSessionKeyPacket pkeskp = (PublicKeyEncryptedSessionKeyPacket)datafile.readPacket();
			// read data packet
			System.out.println("Read data packet...");
			EncryptedDataPacket dp = (EncryptedDataPacket)datafile.readPacket();  // secret primary key packet
			
			// extract session key
			System.out.println("Decrypting secret key data...");
			byte [] pass = {'t','e','s','t'};
			ssp.decryptKeyData(pass);
			
			System.out.println("Extracting session key...");
			RSAAlgorithmParameters keydata = (RSAAlgorithmParameters)ssp.getKeyData();
			
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
			
			PrivateKey privatekey = keydata.getPrivateKey();
			SessionKey sk = pkeskp.getSessionKey(privatekey);
			debug.Debug.println(1,"Session Key");
			debug.Debug.hexDump(1,sk.getSessionKey());
			
			// decrypt data
			System.out.println("Decrypting secret data...");
			dp.decryptAndDecode(sk);
			CompressedDataPacket cdp = (CompressedDataPacket)dp.unpack(0);
			
			// decompress
			System.out.println("Decompressing compressed data packet...");
			LiteralDataPacket lp = (LiteralDataPacket)cdp.unpack(0);
			
			System.out.println("Outputting literal data...");
			System.out.println("FILE : " + lp.getFilename());
			System.out.println("FORMAT : " + lp.getFormat());
			System.out.println("DATA : " + new String(lp.getData()));
			
			datafile.close();
        }
        catch( Exception e )
        {
        	e.printStackTrace();
        	allOK = false;
        }
        
        // tell JUnit the result
        assertTrue( allOK );
    }
    
}
