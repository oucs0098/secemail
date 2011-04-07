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
 * <p>A simple test of the V3 secret key packet.</p>
 * <p>This test creates a V3 packet, writes it out, and attempts to read it back in and decode it.<p>
 */
public class TestV3SecretKeyPacketSimple extends TestCase {
    
    public final String passphrase = "test";
    
    /** Filenames */
    public final String keyoutfile = "TestV3SecretKeyPacketSimple_Key.packet";
    public final String dataoutfile = "TestV3SecretKeyPacketSimple_data.pgp";
    
    /* Literal packet data 1 */
    public final byte format_1 = 't';   
    public final String rawdata_1 = "This is some literal data...";
    public final String filename_1 = "AFilename.dat";
    
    /* Literal packet data 2 */
    public final byte format_2 = 't';
    public final String rawdata_2 = "This is some more literal data";
    public final String filename_2 = "AnotherFilename.dat";
    
    protected SessionKey generateSessionKey( int symmetricAlgorithm ) throws Exception {
            
        KeyGenerator k = KeyGenerator.getInstance(SymmetricAlgorithmSettings.getCipherText(symmetricAlgorithm), "BC");
        k.init(SecureRandom.getInstance("SHA1PRNG"));
        Key key = k.generateKey();

        return new SessionKey(symmetricAlgorithm, key.getEncoded());   
        
    }
    
    protected KeyPair generateKeyPair( int pkAlgorithm ) throws Exception {
        KeyPairGenerator k = KeyPairGenerator.getInstance(PublicKeyAlgorithmSettings.getCipherText(pkAlgorithm), "BC");
        k.initialize(PublicKeyAlgorithmSettings.getDefaultKeySize(pkAlgorithm), SecureRandom.getInstance("SHA1PRNG"));

        return k.generateKeyPair();
    }
    
    protected SymmetricallyEncryptedDataPacket generateDataPacket() throws Exception {
        SymmetricallyEncryptedDataPacket sedp = new SymmetricallyEncryptedDataPacket();

        LiteralDataPacket p1 = new LiteralDataPacket(format_1, filename_1,  rawdata_1.getBytes());

        LiteralDataPacket p2 = new LiteralDataPacket(format_2, filename_2,  rawdata_2.getBytes());

        sedp.add(p1);
        sedp.add(p2);

        return sedp;
    }
    
    protected byte[] generateSalt() throws Exception {
      
        byte salt[] = new byte[8];

        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
        rng.nextBytes(salt);

        return salt;
       
    }
    
    protected boolean compare(SymmetricallyEncryptedDataPacket packet) throws Exception {
        
        boolean result = true;
        
        System.out.println("  Comparing packet 1...");
            
        LiteralDataPacket lp1 = (LiteralDataPacket)packet.unpack(0);

        // format
        System.out.print("    Format... ");
        if (lp1.getFormat()==format_1) {
            // ok
            System.out.println("Ok");
        } else {
            // error
            System.out.print(lp1.getFormat());
            System.out.println("...Error!");
            result = false;
        }

        // Filename
        System.out.print("    Filename... ");
        if (lp1.getFilename().compareTo(filename_1)==0) {
            // ok
            System.out.println("Ok");
        } else {
            // error
            System.out.print(lp1.getFilename());
            System.out.println("Error!");
            result = false;
        }

        // data only
        System.out.print("    Data... ");
        if (new String(lp1.getData()).compareTo(rawdata_1)==0) {
            // ok
            System.out.println("Ok");
        } else {
            // error
            System.out.println("Error!");
            result = false;
        }

        // Date
        System.out.print("    Date is... ");
        System.out.println(new Date(lp1.getModDate()*1000).toString());


    // compare packet 2
    System.out.println("  Comparing packet 2...");

        LiteralDataPacket lp2 = (LiteralDataPacket)packet.unpack(1);

        // format
        System.out.print("    Format... ");
        if (lp2.getFormat()==format_2) {
            // ok
            System.out.println("Ok");
        } else {
            // error
            System.out.print(lp2.getFormat());
            System.out.println("...Error!");
            result = false;
        }

        // Filename
        System.out.print("    Filename... ");
        if (lp2.getFilename().compareTo(filename_2)==0) {
            // ok
            System.out.println("Ok");
        } else {
            // error
            System.out.print(lp2.getFilename());
            System.out.println("Error!");
            result = false;
        }

        // data only
        System.out.print("    Data... ");
        if (new String(lp2.getData()).compareTo(rawdata_2)==0) {
            // ok
            System.out.println("Ok");
        } else {
            // error
            System.out.println(new String(lp2.getData()));
            System.out.println("Error!");
            result = false;
        }

        // Date
        System.out.print("    Date is... ");
        System.out.println(new Date(lp2.getModDate()*1000).toString());
        
        return result;
    }
    
    
    /** <p>Execute the test.</p>
     * <p>You should implement this method with your test. Return true if the test
     * was successful, otherwise return false.</p>
     * @throws Exception if something went wrong.
     *
     */
    private boolean doTest( int pkAlgorithm, int symmetricAlgorithm, int hashAlgorithm )
    {
		boolean allOK = true;
		
		try
		{
			// generate and write demo packet.
			System.out.println("Adding Bouncy Castle JCE provider...");
			Security.addProvider(new BouncyCastleProvider());
			
			// generate key pair
			System.out.println("Generating public/private keypair...");
			KeyPair kp = generateKeyPair( pkAlgorithm );
			
			System.out.println("Converting to algorithm param...");
			RSAAlgorithmParameters params = new RSAAlgorithmParameters();//(RSAAlgorithmParameters)generateAlgorithmParameters(kp);
			params.wrapPublicKey(kp.getPublic());
			params.wrapPrivateKey(kp.getPrivate());
			//params.generateKeyPair(PublicKeyAlgorithmSettings.getDefaultKeySize(PKAlgorithm),SecureRandom.getInstance("SHA1PRNG"));
			
			// generate a salt
			System.out.println("Generating salt...");
			byte [] salt = generateSalt();
			
			// generate secret key packet
			System.out.println("Generating secret key packet...");
			SecretKeyPacket skp = new SecretKeyPacket(0,pkAlgorithm, symmetricAlgorithm, new S2K(hashAlgorithm, salt), passphrase.getBytes(), params);
			
			// save key
			System.out.println("Writing secret key packet to "+keyoutfile+"...");
			OpenPGPPacketOutputStream skout_stream = new OpenPGPPacketOutputStream(new FileOutputStream(keyoutfile));
			skout_stream.writePacket(skp);
			skout_stream.close();
			
			// generate session key
			System.out.println("Generating session key...");
			SessionKey sk = generateSessionKey( symmetricAlgorithm );
			
			// loading secret + public key
			System.out.println("Loading secret + public key material from "+keyoutfile+"...");
			OpenPGPPacketInputStream skin_stream = new OpenPGPPacketInputStream(new FileInputStream(keyoutfile));
			SecretKeyPacket r_skp = (SecretKeyPacket)skin_stream.readPacket();
			skin_stream.close();
			
			// generate pk session key
			System.out.println("Generating PK encrypted session key packet...");
			byte keyid[] = new byte[8]; for (int n = 0; n < 8; n++) keyid[n]=0;
			PublicKey publickey = params.getPublicKey();
			PublicKeyEncryptedSessionKeyPacket pkeskp = new PublicKeyEncryptedSessionKeyPacket(publickey,keyid,pkAlgorithm,sk);
			
			// generate data packet
			System.out.println("Generating and encrypting data packet...");
			SymmetricallyEncryptedDataPacket dp = generateDataPacket();
			dp.encryptAndEncode(sk);
			
			// save data packet
			System.out.println("Saving data to "+dataoutfile+"...");
			OpenPGPPacketOutputStream data_outstream = new OpenPGPPacketOutputStream(new FileOutputStream(dataoutfile));
			data_outstream.writePacket(pkeskp);
			data_outstream.writePacket(dp);
			data_outstream.close();
			
			// load data packet
			System.out.println("Loading data from "+dataoutfile+"...");
			OpenPGPPacketInputStream data_instream = new OpenPGPPacketInputStream(new FileInputStream(dataoutfile));
			PublicKeyEncryptedSessionKeyPacket r_pkeskp = (PublicKeyEncryptedSessionKeyPacket)data_instream.readPacket();
			SymmetricallyEncryptedDataPacket r_dp = (SymmetricallyEncryptedDataPacket)data_instream.readPacket();
			data_instream.close();
			
			// extracting sessionkey
			System.out.println("Extracting private key...");
			r_skp.decryptKeyData(passphrase.getBytes());
			System.out.println("Extracting session key...");
			SessionKey r_sk = r_pkeskp.getSessionKey(r_skp.getKeyData().getPrivateKey());//r_kp.getPrivate());*/
			
			
			// display private and public components
			RSAAlgorithmParameters keydata2 = (RSAAlgorithmParameters)r_skp.getKeyData();
			
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
			
			// decode
			System.out.println("Decrypting data packet...");
			r_dp.decryptAndDecode(r_sk);
			
			// compare
			System.out.println("Comparing...");
			if (compare(r_dp)==false) 
				allOK = false;
		}
		catch( Exception e )
		{
			e.printStackTrace();
			allOK = false;
		}
		
		// if we got this far then the test should have gone ok
		return allOK;
    }
	
	public void testV3SKPSimpleWithRSAAndIDEAAndMD5()
	{
		assertTrue( doTest( 
				PublicKeyAlgorithmSettings.RSA_ENCRYPTSIGN, SymmetricAlgorithmSettings.IDEA, HashAlgorithmSettings.MD5 ) );
	}
}
