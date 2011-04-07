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

import core.keyhandlers.*;
import core.algorithmhandlers.openpgp.*;
import core.algorithmhandlers.openpgp.packets.*;
import core.algorithmhandlers.openpgp.util.*;
import core.algorithmhandlers.keymaterial.*;
import core.keyhandlers.parameters.*;
import core.keyhandlers.identifiers.*;
import org.bouncycastle.jce.provider.*;
import junit.framework.TestCase;
import java.security.*;
import java.io.*;
import java.util.*;

/**
 * <p>This class will test public and private keyrings.</p>
 * <p>The test will create a public and private keyring, write some keys to the file, retrieve them
 * and delete some.</p>
 * <p>To be absolutely sure of compatibility you should attempt to view the keyring files in a third party
 * pgp application.</p>
 */
public class TestOpenPGPKeyrings extends TestCase {

    public final String secretkeyring_fn = "TestOpenPGPKeyrings_secret.pgp";
    public final String publickeyring_fn = "TestOpenPGPKeyrings_public.pgp";

	public void debugPrintKey(RSAAlgorithmParameters keydata) 
	{
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
	}

    /** A quick method that will read through a given keyring file and return an ordered array of
     * all keys and subkeys in the packet. */
    public KeyPacket[] fetchKeys(String keyfile) throws Exception {
        KeyPacket ret[] = null;

        OpenPGPPacketInputStream in = new OpenPGPPacketInputStream(new FileInputStream(keyfile));

        Packet p = null;
        do {

            p = in.readPacket();

            if ((p!=null) && (p instanceof KeyPacket)) {

                if (ret == null) {
                    ret = new KeyPacket[1];
                } else {
                    KeyPacket tmp[] = ret;
                    ret = new KeyPacket[tmp.length+1];

                    for (int n = 0; n < tmp.length; n++)
                        ret[n] = tmp[n];
                }

                ret[ret.length -1] = (KeyPacket)p;
            }

        } while (p!=null);

        in.close();
        return ret;
    }

    /**
     * <p>A quick method to compare two byte arrays.</p>
     * @return true if the two byte arrays match, false if not.
     */
    private boolean compareByteArrays(byte[] one, byte[] two) {
        if (one.length != two.length)
            return false;

        for (int n = 0; n < one.length; n++)
            if (one[n]!=two[n])
                return false;

        return true;
    }
    
    /** Parse two keyrings and make sure that the public and private key pairs have matching key ids. */
    private void compareKeyIDs(String pubkeyring, String prikeyring) throws Exception {
        
        KeyPacket publicKeys[] = fetchKeys(pubkeyring);
        KeyPacket secretKeys[] = fetchKeys(prikeyring);
        
        if (publicKeys.length != secretKeys.length)
            throw new Exception("Public and private keyrings have different numbers of keys in them.");
        
        for (int n = 0; n < publicKeys.length; n++) {
            byte [] pub = publicKeys[n].getKeyID();
            byte [] sec = secretKeys[n].getKeyID();
            
            System.out.println("  Comparing key " + n + ":");
                System.out.print("    Public: 0x"); debug.Debug.hexDump(1, pub);
                System.out.print("    Private: 0x"); debug.Debug.hexDump(1, sec);
                
            if (!compareByteArrays(pub, sec))
                throw new Exception("Key IDs for keypair " + n + " are different!");
        }
        
    }

    /** A method that compares two keys and returns true if they match. */
    public boolean compareKeys(boolean secret, AsymmetricAlgorithmParameters one, AsymmetricAlgorithmParameters two) throws Exception 
    {
        RSAAlgorithmParameters a = (RSAAlgorithmParameters)one;
        RSAAlgorithmParameters b = (RSAAlgorithmParameters)two;

        if (!compareByteArrays(a.getN().toByteArray(),b.getN().toByteArray())) throw new Exception("N value does not match!");
        if (!compareByteArrays(a.getE().toByteArray(),b.getE().toByteArray())) throw new Exception("E value does not match!");
        if (secret) 
        {
            if (!compareByteArrays(a.getD().toByteArray(),b.getD().toByteArray())) throw new Exception("D value does not match!");
            if (!compareByteArrays(a.getP().toByteArray(),b.getP().toByteArray())) throw new Exception("P value does not match!");
            if (!compareByteArrays(a.getQ().toByteArray(),b.getQ().toByteArray())) throw new Exception("Q value does not match!");
            if (!compareByteArrays(a.getU().toByteArray(),b.getU().toByteArray())) throw new Exception("U value does not match!");
        }

        return true;
    }

    /** <p>Execute the test.</p>
     * <p>You should implement this method with your test. Return true if the test
     * was successful, otherwise return false.</p>
     * @throws Exception if something went wrong.
     */
    public boolean doTest()
    {
        Date now = new Date();
        boolean allOK = true;
        
        try
        {
	        // add bouncycastle provider
	        System.out.println("Adding Bouncy Castle JCE provider...");
	            Security.addProvider(new BouncyCastleProvider());
	
	        for (int pass = 0; pass < 2; pass++) {
	
	            String publickeyring = "pass_" + (pass+1) + "_" + publickeyring_fn;
	            String secretkeyring = "pass_" + (pass+1) + "_" + secretkeyring_fn;
	
	            byte [] kid = {1,2,3,4,5,6,7,8};
	
	            System.out.println(":: Keyring tests phase " + (pass+1) + " =============================================== ::");
	
				// remove public & private keyrings
				System.out.println("Removing any keyrings left from previous test...");
				File f1 = new File(secretkeyring); f1.delete();
				File f2 = new File(publickeyring); f2.delete();
				
				// create public & private keyrings
				System.out.println("Creating public and secret keyrings...");
				OpenPGPSecretKeyring secretRing = new OpenPGPSecretKeyring(secretkeyring, null);
				OpenPGPPublicKeyring publicRing = new OpenPGPPublicKeyring(publickeyring, null);
	
				// create key 1 & subkey
				System.out.println("Creating key 1 (primary + subkey)...");
				// Create keys
				RSAAlgorithmParameters k1[] = new RSAAlgorithmParameters[2];
				k1[0] = new RSAAlgorithmParameters();
				k1[0].generateKeyPair(PublicKeyAlgorithmSettings.getDefaultKeySize(1), SecureRandom.getInstance("SHA1PRNG"));
				k1[1] = new RSAAlgorithmParameters();
				k1[1].generateKeyPair(PublicKeyAlgorithmSettings.getDefaultKeySize(1), SecureRandom.getInstance("SHA1PRNG"));
				
				debug.Debug.println(1, "*** Primary Key 1 ***");
				debugPrintKey(k1[0]);
				debug.Debug.println(1, "*** Sub Key 1 ***");
				debugPrintKey(k1[1]);
				
				KeyData k1_key[] = new KeyData[2];
				k1_key[0] = new KeyData(k1[0]);
				k1_key[1] = new KeyData(k1[1]);
				
				// Create key identifiers
				OpenPGPStandardKeyIdentifier k1_uid[] = new OpenPGPStandardKeyIdentifier[2];
				k1_uid[0] = new OpenPGPStandardKeyIdentifier("Key One".getBytes(), "key1@example.com".getBytes());
				
				// Parameters
				byte [] symAlgPrefs = {1,2,3};
				byte [] hashPrefs = {2};
				byte [] compressPrefs = {2,1};
				OpenPGPAddKeyParameters k1_pubparam[] = new OpenPGPAddKeyParameters[2];
				k1_pubparam[0] = new OpenPGPAddKeyParameters(now, 1, 1, symAlgPrefs, hashPrefs, compressPrefs);
				k1_pubparam[1] = new OpenPGPAddKeyParameters(now, 1, 1, symAlgPrefs, hashPrefs, compressPrefs);
				
				OpenPGPAddSecretKeyParameters k1_secparam[] = new OpenPGPAddSecretKeyParameters[2];
				
				k1_secparam[0] = new OpenPGPAddSecretKeyParameters(now, 1, 1, null, null, null, "test".getBytes("UTF8"), SymmetricAlgorithmSettings.IDEA, HashAlgorithmSettings.SHA1);
				k1_secparam[1] = new OpenPGPAddSecretKeyParameters(now, 1, 1, null, null, null, "test".getBytes("UTF8"), SymmetricAlgorithmSettings.IDEA, HashAlgorithmSettings.SHA1);
	
				// create key 2
				System.out.println("Creating key 2...");
				RSAAlgorithmParameters k2[] = new RSAAlgorithmParameters[1];
				k2[0] = new RSAAlgorithmParameters();
				k2[0].generateKeyPair(PublicKeyAlgorithmSettings.getDefaultKeySize(1), SecureRandom.getInstance("SHA1PRNG"));
				
				debug.Debug.println(1, "*** Key 2 ***");
				debugPrintKey(k2[0]);
				
				KeyData k2_key[] = new KeyData[1];
				k2_key[0] = new KeyData(k2[0]);
				
				OpenPGPStandardKeyIdentifier k2_uid[] = new OpenPGPStandardKeyIdentifier[1];
				k2_uid[0] = new OpenPGPStandardKeyIdentifier("Key Two".getBytes(), "key2@example.com".getBytes());
				
				OpenPGPAddKeyParameters k2_pubparam[] = new OpenPGPAddKeyParameters[1];
				k2_pubparam[0] = new OpenPGPAddKeyParameters(now, 1, 1, null, null, null);
				
				OpenPGPAddSecretKeyParameters k2_secparam[] = new OpenPGPAddSecretKeyParameters[1];
				k2_secparam[0] = new OpenPGPAddSecretKeyParameters(now, 1, 1, null, null, null, "test".getBytes(), SymmetricAlgorithmSettings.CAST5, HashAlgorithmSettings.SHA1);
	
				// create key 3
				System.out.println("Creating key 3...");
				RSAAlgorithmParameters k3[] = new RSAAlgorithmParameters[1];
				k3[0] = new RSAAlgorithmParameters();
				k3[0].generateKeyPair(PublicKeyAlgorithmSettings.getDefaultKeySize(1), SecureRandom.getInstance("SHA1PRNG"));
				
				debug.Debug.println(1, "*** Key 3 ***");
				debugPrintKey(k2[0]);
				
				KeyData k3_key[] = new KeyData[1];
				k3_key[0] = new KeyData(k3[0]);
				
				OpenPGPStandardKeyIdentifier k3_uid[] = new OpenPGPStandardKeyIdentifier[1];
				k3_uid[0] = new OpenPGPStandardKeyIdentifier("Key Three".getBytes(), "key3@example.com".getBytes());
				
				OpenPGPAddKeyParameters k3_pubparam[] = new OpenPGPAddKeyParameters[1];
				k3_pubparam[0] = new OpenPGPAddKeyParameters(now, 1, 1, null, null, null);
				
				OpenPGPAddSecretKeyParameters k3_secparam[] = new OpenPGPAddSecretKeyParameters[1];
				k3_secparam[0] = new OpenPGPAddSecretKeyParameters(now, 1, 1, null, null, null, "test".getBytes(), SymmetricAlgorithmSettings.CAST5, HashAlgorithmSettings.SHA1);
	
				// add rings
				System.out.println("Adding key 1 (primary + subkey)...");
				secretRing.addKeys(k1_key, k1_uid, k1_secparam);
				publicRing.addKeys(k1_key, k1_uid, k1_pubparam);
				System.out.println("Adding key 2...");
				secretRing.addKeys(k2_key, k2_uid, k2_secparam);
				publicRing.addKeys(k2_key, k2_uid, k2_pubparam);
				System.out.println("Adding key 3...");
				secretRing.addKeys(k3_key, k3_uid, k3_secparam);
				publicRing.addKeys(k3_key, k3_uid, k3_pubparam);
				
				System.out.println("Validating keyring...");
				compareKeyIDs(publickeyring, secretkeyring);
				
				System.out.println("Adding keys to ascii files...");
				OpenPGPAscSecretFile ascsecretRing = new OpenPGPAscSecretFile(secretkeyring+".asc", null);
				OpenPGPAscPublicFile ascpublicRing = new OpenPGPAscPublicFile(publickeyring+".asc", null);
				ascsecretRing.addKeys(k1_key, k1_uid, k1_secparam);
				ascpublicRing.addKeys(k1_key, k1_uid, k1_pubparam);
				
	            // Find and verify keys
	            System.out.println("+++ Secret Keyring Seek Tests +++");
	            if (pass == 0) 
	            { // look using user + email
					System.out.print("Look for non-existant key using UID in secret key...");
					KeyObject [] keys = secretRing.findKeys(new OpenPGPStandardKeyIdentifier("Foo".getBytes(), "bar@example.com".getBytes()), new OpenPGPFindKeyParameters("test".getBytes()));
					if (keys!=null) 
						throw new Exception("findKeys didn't return null"); 
					else 
						System.out.println("OK");
					
					System.out.print("Finding key 1 (primary key) using UID in ASCII secret key...");
					keys = ascsecretRing.findKeys(new OpenPGPStandardKeyIdentifier("Key One".getBytes(), "key1@example.com".getBytes()), new OpenPGPFindKeyParameters("test".getBytes()));
					System.out.print("Got back " + keys.length + " keys...");
					System.out.print("Comparing...");
					if (compareKeys(true, keys[0].getKeyData().getKey(),k1[0]))
					    System.out.println("OK");
					
					System.out.print("Finding key 1 (sub key) using UID in ASCII secret key...");
					keys = ascsecretRing.findKeys(new OpenPGPStandardKeyIdentifier("Key One".getBytes(), "key1@example.com".getBytes()), new OpenPGPFindKeyParameters("test".getBytes()));
					System.out.print("Got back " + keys.length + " keys...");
					System.out.print("Comparing...");
					if (compareKeys(true, keys[1].getKeyData().getKey(),k1[1]))
					    System.out.println("OK");
	                
					System.out.print("Finding key 1 (primary key) using UID in secret key...");
					keys = secretRing.findKeys(new OpenPGPStandardKeyIdentifier("Key One".getBytes(), "key1@example.com".getBytes()), new OpenPGPFindKeyParameters("test".getBytes()));
					System.out.print("Got back " + keys.length + " keys...");
					System.out.print("Comparing...");
					if (compareKeys(true, keys[0].getKeyData().getKey(),k1[0]))
					    System.out.println("OK");
					
					System.out.print("Finding key 1 (sub key) using UID in secret key...");
					keys = secretRing.findKeys(new OpenPGPStandardKeyIdentifier("Key One".getBytes(), "key1@example.com".getBytes()), new OpenPGPFindKeyParameters("test".getBytes()));
					System.out.print("Got back " + keys.length + " keys...");
					System.out.print("Comparing...");
					if (compareKeys(true, keys[1].getKeyData().getKey(),k1[1]))
					    System.out.println("OK");
					
					System.out.print("Finding key 2 using UID in secret key...");
					keys = secretRing.findKeys(new OpenPGPStandardKeyIdentifier("Key Two".getBytes(), "key2@example.com".getBytes()), new OpenPGPFindKeyParameters("test".getBytes()));
					System.out.print("Got back " + keys.length + " keys...");
					System.out.print("Comparing...");
					if (compareKeys(true, keys[0].getKeyData().getKey(),k2[0]))
					    System.out.println("OK");
					
					System.out.print("Finding key 3 using UID in secret key...");
					keys = secretRing.findKeys(new OpenPGPStandardKeyIdentifier("Key Three".getBytes(), "key3@example.com".getBytes()), new OpenPGPFindKeyParameters("test".getBytes()));
					System.out.print("Got back " + keys.length + " keys...");
					System.out.print("Comparing...");
					if (compareKeys(true, keys[0].getKeyData().getKey(),k3[0]))
					    System.out.println("OK");
	            }
	
	            if (pass == 1) 
	            { // look using KeyID
					System.out.println("Parsing " + secretkeyring + "...");
					KeyPacket secretKeys[] = fetchKeys(publickeyring);
					
					System.out.print("Look for non-existant key using KeyID in secret key...");
					KeyObject[] keys = secretRing.findKeys(new OpenPGPKeyIDKeyIdentifier(kid), new OpenPGPFindKeyParameters("test".getBytes()));
					if (keys!=null) 
						throw new Exception("findKeys didn't return null"); 
					else 
						System.out.println("OK");
					
					System.out.print("Finding key 1 (primary key) using KeyID in ASCII secret key...");
					keys = ascsecretRing.findKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[0].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					System.out.print("Got back " + keys.length + " keys...");
					System.out.print("Comparing...");
					if (compareKeys(true, keys[0].getKeyData().getKey(),k1[0]))
					    System.out.println("OK");
					
					System.out.print("Finding key 1 (sub key) using KeyID in ASCII secret key...");
					keys = ascsecretRing.findKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[1].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					System.out.print("Got back " + keys.length + " keys...");
					System.out.print("Comparing...");
					if (compareKeys(true, keys[0].getKeyData().getKey(),k1[1]))
					    System.out.println("OK");
					
					System.out.print("Finding key 1 (primary key) using KeyID in secret key...");
					keys = secretRing.findKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[0].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					System.out.print("Got back " + keys.length + " keys...");
					System.out.print("Comparing...");
					if (compareKeys(true, keys[0].getKeyData().getKey(),k1[0]))
					    System.out.println("OK");
					
					System.out.print("Finding key 1 (sub key) using KeyID in secret key...");
					keys = secretRing.findKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[1].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					System.out.print("Got back " + keys.length + " keys...");
					System.out.print("Comparing...");
					if (compareKeys(true, keys[0].getKeyData().getKey(),k1[1]))
					    System.out.println("OK");
					
					System.out.print("Finding key 2 using KeyID in secret key...");
					keys = secretRing.findKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[2].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					System.out.print("Got back " + keys.length + " keys...");
					System.out.print("Comparing...");
					if (compareKeys(true, keys[0].getKeyData().getKey(),k2[0]))
					    System.out.println("OK");
					
					System.out.print("Finding key 3 using KeyID in secret key...");
					keys = secretRing.findKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[3].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					System.out.print("Got back " + keys.length + " keys...");
					System.out.print("Comparing...");
					if (compareKeys(true, keys[0].getKeyData().getKey(),k3[0]))
					    System.out.println("OK");
					
					System.out.print("Finding keys using wildcard KeyID in secret key...");
					byte wildcard[] = {0,0,0,0,0,0,0,0}; 
					keys = secretRing.findKeys(new OpenPGPKeyIDKeyIdentifier(wildcard), new OpenPGPFindKeyParameters("test".getBytes()));
					System.out.print("Got back " + keys.length + " keys...");
					if (keys.length!=4) 
					    throw new Exception("Wildcard search didn't return the expected number of keys!");
					else
					    System.out.println("OK");
	                
	            }
	
	            System.out.println("+++ Public Keyring Seek Tests +++");
	            if (pass==0) 
	            { // look at uid
					System.out.print("Look for non-existant key using UID in public key...");
					KeyObject[] keys = publicRing.findKeys(new OpenPGPStandardKeyIdentifier("Foo".getBytes(), "bar@example.com".getBytes()), null);
					if (keys!=null) 
						throw new Exception("findKeys didn't return null"); 
					else 
						System.out.println("OK");
					
					System.out.print("Finding key 1 (primary key) using UID in ASCII public key...");
					keys = ascpublicRing.findKeys(new OpenPGPStandardKeyIdentifier("Key One".getBytes(), "key1@example.com".getBytes()), null);
					System.out.print("Got back " + keys.length + " keys...");
					System.out.print("Comparing...");
					if (compareKeys(false, keys[0].getKeyData().getKey(),k1[0]))
					    System.out.println("OK");
					
					System.out.print("Finding key 1 (sub key) using UID in ASCII public key...");
					keys = ascpublicRing.findKeys(new OpenPGPStandardKeyIdentifier("Key One".getBytes(), "key1@example.com".getBytes()), null);
					System.out.print("Got back " + keys.length + " keys...");
					System.out.print("Comparing...");
					if (compareKeys(false, keys[1].getKeyData().getKey(),k1[1]))
					    System.out.println("OK");
					
					
					
					System.out.print("Finding key 1 (primary key) using UID in public key...");
					keys = publicRing.findKeys(new OpenPGPStandardKeyIdentifier("Key One".getBytes(), "key1@example.com".getBytes()), null);
					System.out.print("Got back " + keys.length + " keys...");
					System.out.print("Comparing...");
					if (compareKeys(false, keys[0].getKeyData().getKey(),k1[0]))
					    System.out.println("OK");
					
					System.out.print("Finding key 1 (sub key) using UID in public key...");
					keys = publicRing.findKeys(new OpenPGPStandardKeyIdentifier("Key One".getBytes(), "key1@example.com".getBytes()), null);
					System.out.print("Got back " + keys.length + " keys...");
					System.out.print("Comparing...");
					if (compareKeys(false, keys[1].getKeyData().getKey(),k1[1]))
					    System.out.println("OK");
					
					System.out.print("Finding key 2 using UID in public key...");
					keys = publicRing.findKeys(new OpenPGPStandardKeyIdentifier("Key Two".getBytes(), "key2@example.com".getBytes()), null);
					System.out.print("Got back " + keys.length + " keys...");
					System.out.print("Comparing...");
					if (compareKeys(false, keys[0].getKeyData().getKey(),k2[0]))
					    System.out.println("OK");
					
					System.out.print("Finding key 3 using UID in public key...");
					keys = publicRing.findKeys(new OpenPGPStandardKeyIdentifier("Key Three".getBytes(), "key3@example.com".getBytes()), null);
					System.out.print("Got back " + keys.length + " keys...");
					System.out.print("Comparing...");
					if (compareKeys(false, keys[0].getKeyData().getKey(),k3[0]))
					    System.out.println("OK");
				}
	            
				if (pass==1) 
				{ // look at kid
					System.out.println("Parsing " + publickeyring + "...");
					KeyPacket publicKeys[] = fetchKeys(secretkeyring);
					
					System.out.print("Look for non-existant key using KeyID in public key...");
					KeyObject[] keys = publicRing.findKeys(new OpenPGPKeyIDKeyIdentifier(kid), null);
					if (keys!=null) 
						throw new Exception("findKeys didn't return null"); 
					else 
						System.out.println("OK");
					
					System.out.print("Finding key 1 (primary key) using KeyID in ASCII public key...");
					keys = ascpublicRing.findKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[0].getKeyID()), null);
					System.out.print("Got back " + keys.length + " keys...");
					System.out.print("Comparing...");
					if (compareKeys(false, keys[0].getKeyData().getKey(),k1[0]))
					    System.out.println("OK");
					
					System.out.print("Finding key 1 (sub key) using KeyID in ASCII public key...");
					keys = ascpublicRing.findKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[1].getKeyID()), null);
					System.out.print("Got back " + keys.length + " keys...");
					System.out.print("Comparing...");
					if (compareKeys(false, keys[0].getKeyData().getKey(),k1[1]))
					    System.out.println("OK");
					
					
					System.out.print("Finding key 1 (primary key) using KeyID in public key...");
					keys = publicRing.findKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[0].getKeyID()), null);
					System.out.print("Got back " + keys.length + " keys...");
					System.out.print("Comparing...");
					if (compareKeys(false, keys[0].getKeyData().getKey(),k1[0]))
					    System.out.println("OK");
					
					System.out.print("Finding key 1 (sub key) using KeyID in public key...");
					keys = publicRing.findKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[1].getKeyID()), null);
					System.out.print("Got back " + keys.length + " keys...");
					System.out.print("Comparing...");
					if (compareKeys(false, keys[0].getKeyData().getKey(),k1[1]))
					    System.out.println("OK");
					
					System.out.print("Finding key 2 using KeyID in public key...");
					keys = publicRing.findKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[2].getKeyID()), null);
					System.out.print("Got back " + keys.length + " keys...");
					System.out.print("Comparing...");
					if (compareKeys(false, keys[0].getKeyData().getKey(),k2[0]))
					    System.out.println("OK");
					
					System.out.print("Finding key 3 using KeyID in public key...");
					keys = publicRing.findKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[3].getKeyID()), null);
					System.out.print("Got back " + keys.length + " keys...");
					System.out.print("Comparing...");
					if (compareKeys(false, keys[0].getKeyData().getKey(),k3[0]))
					    System.out.println("OK");
					
					System.out.print("Finding keys using wildcard KeyID in public key...");
					byte wildcard[] = {0,0,0,0,0,0,0,0}; 
					keys = publicRing.findKeys(new OpenPGPKeyIDKeyIdentifier(wildcard), null);
					System.out.print("Got back " + keys.length + " keys...");
					if (keys.length!=4) 
					    throw new Exception("Wildcard search didn't return the expected number of keys!");
					else
					    System.out.println("OK");
	            }
	
				System.out.println("+++ Deleting ASCII files...");
				ascsecretRing.removeKeys(new OpenPGPStandardKeyIdentifier("Key One".getBytes(), "key1@example.com".getBytes()), new OpenPGPFindKeyParameters("test".getBytes()));
				ascpublicRing.removeKeys(new OpenPGPStandardKeyIdentifier("Key One".getBytes(), "key1@example.com".getBytes()), null);
	
				System.out.println("+++ Secret Keyring delete Tests +++");
				if (pass == 0) 
				{ // look at uid
					System.out.print("Attempt to delete a non existant key UID in secret key...");
					if (secretRing.removeKeys(new OpenPGPStandardKeyIdentifier("Foo".getBytes(), "bar@example.com".getBytes()), null)!=0)
					    throw new Exception("removeKeys didn't return 0");
					else
					    System.out.println("OK");
					
					// delete primary and seconday
					System.out.print("Key 1 (primary key) using UID in secret key...");
					if (secretRing.removeKeys(new OpenPGPStandardKeyIdentifier("Key One".getBytes(), "key1@example.com".getBytes()), null)!=2)
					    throw new Exception("Didn't remove 2 keys");
					else
					    System.out.println("OK");
					
					// find
					System.out.print("Finding key 1 using UID in secret key...");
					KeyObject[] keys = secretRing.findKeys(new OpenPGPStandardKeyIdentifier("Key One".getBytes(), "key1@example.com".getBytes()), new OpenPGPFindKeyParameters("test".getBytes()));
					if (keys!=null) 
						throw new Exception("Key has not been deleted!"); 
					else 
						System.out.println("Deleted");
					
					
					System.out.print("Finding key 2 using UID in secret key...");
					keys = secretRing.findKeys(new OpenPGPStandardKeyIdentifier("Key Two".getBytes(), "key2@example.com".getBytes()), new OpenPGPFindKeyParameters("test".getBytes()));
					if ((keys==null)||(keys.length!=1)) 
						throw new Exception("Key has been deleted!"); 
					else 
						System.out.print("Found...");
					System.out.print("Comparing...");
					if (compareKeys(true, keys[0].getKeyData().getKey(),k2[0]))
						System.out.println("OK");
		
					System.out.print("Finding key 3 using UID in secret key...");
					keys = secretRing.findKeys(new OpenPGPStandardKeyIdentifier("Key Three".getBytes(), "key3@example.com".getBytes()), new OpenPGPFindKeyParameters("test".getBytes()));
					if ((keys==null)||(keys.length!=1)) 
						throw new Exception("Key has been deleted!"); 
					else 
						System.out.print("Found...");
					System.out.print("Comparing...");
					if (compareKeys(true, keys[0].getKeyData().getKey(),k3[0]))
						System.out.println("OK");
		
		
					// delete key 2
					System.out.print("Key 2 using UID in secret key...");
					if (secretRing.removeKeys(new OpenPGPStandardKeyIdentifier("Key Two".getBytes(), "key2@example.com".getBytes()), null)!=1)
						throw new Exception("Didn't remove key");
					else
						System.out.println("OK");
		
					// find
					System.out.print("Finding key 2 using UID in secret key...");
					keys = secretRing.findKeys(new OpenPGPStandardKeyIdentifier("Key Two".getBytes(), "key2@example.com".getBytes()), new OpenPGPFindKeyParameters("test".getBytes()));
					if (keys!=null) 
						throw new Exception("Key has not been deleted!"); 
					else 
						System.out.println("Deleted");
					
					System.out.print("Finding key 3 using UID in secret key...");
					keys = secretRing.findKeys(new OpenPGPStandardKeyIdentifier("Key Three".getBytes(), "key3@example.com".getBytes()), new OpenPGPFindKeyParameters("test".getBytes()));
					if ((keys==null)||(keys.length!=1)) 
						throw new Exception("Key has been deleted!"); 
					else 
						System.out.print("Found...");
					System.out.print("Comparing...");
					if (compareKeys(true, keys[0].getKeyData().getKey(),k3[0]))
						System.out.println("OK");
					
					// delete key 3
					System.out.print("Key 3 using UID in secret key...");
					if (secretRing.removeKeys(new OpenPGPStandardKeyIdentifier("Key Three".getBytes(), "key3@example.com".getBytes()), null)!=1)
						throw new Exception("Didn't remove key");
					else
						System.out.println("OK");
					
					// find
					System.out.print("Finding key 3 using UID in secret key...");
					keys = secretRing.findKeys(new OpenPGPStandardKeyIdentifier("Key Three".getBytes(), "key3@example.com".getBytes()), new OpenPGPFindKeyParameters("test".getBytes()));
					if (keys!=null) 
						throw new Exception("Key has not been deleted!"); 
					else 
						System.out.println("Deleted");
				}
				
	            if (pass == 1) 
	            { // look at kid
					System.out.println("Parsing " + secretkeyring + "...");
					KeyPacket secretKeys[] = fetchKeys(secretkeyring);
					
					System.out.print("Attempt to delete a non existant key ID in secret key...");
					if (secretRing.removeKeys(new OpenPGPKeyIDKeyIdentifier(kid), null)!=0)
					    throw new Exception("removeKeys didn't return 0"); 
					else 
						System.out.println("OK");
					
					// delete primary and seconday
					System.out.print("Key 1 (primary key) using KeyID in secret key...");
					if (secretRing.removeKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[0].getKeyID()), null)!=2)
					    throw new Exception("Didn't remove 2 keys"); 
					else 
						System.out.println("OK");
					
					System.out.print("Finding key 1 (primary key) using KeyID in secret key...");
					KeyObject [] keys = secretRing.findKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[0].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if (keys!=null) 
						throw new Exception("Key has not been deleted!"); 
					else 
						System.out.println("Deleted");
					
					System.out.print("Finding key 1 (sub key) using KeyID in secret key...");
					keys = secretRing.findKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[1].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if (keys!=null) 
						throw new Exception("Key has not been deleted!"); 
					else 
						System.out.println("Deleted");
					
					System.out.print("Finding key 2 using KeyID in secret key...");
					keys = secretRing.findKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[2].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if ((keys==null)||(keys.length!=1)) 
						throw new Exception("Key has been deleted!"); 
					else 
						System.out.print("Found...");
					System.out.print("Comparing...");
					if (compareKeys(true, keys[0].getKeyData().getKey(),k2[0]))
						System.out.println("OK");
					
					System.out.print("Finding key 3 using KeyID in secret key...");
					keys = secretRing.findKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[3].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if ((keys==null)||(keys.length!=1)) 
						throw new Exception("Key has been deleted!"); 
					else 
						System.out.print("Found...");
					System.out.print("Comparing...");
					if (compareKeys(true, keys[0].getKeyData().getKey(),k3[0]))
						System.out.println("OK");
	
	
					// delete key 2
					System.out.print("Key 2 using KeyID in secret key...");
					if (secretRing.removeKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[2].getKeyID()), null)!=1)
					    throw new Exception("Didn't remove key"); 
					else 
						System.out.println("OK");
					
					System.out.print("Finding key 2 using KeyID in secret key...");
					keys = secretRing.findKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[2].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if (keys!=null) 
						throw new Exception("Key has not been deleted!"); 
					else 
						System.out.println("Deleted");
					
					System.out.print("Finding key 3 using KeyID in secret key...");
					keys = secretRing.findKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[3].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if ((keys==null)||(keys.length!=1)) 
						throw new Exception("Key has been deleted!"); 
					else 
						System.out.print("Found...");
					System.out.print("Comparing...");
					if (compareKeys(true, keys[0].getKeyData().getKey(),k3[0]))
						System.out.println("OK");
					
					// delete key 3
					System.out.print("Key 3 using KeyID in secret key...");
					if (secretRing.removeKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[3].getKeyID()), null)!=1)
					    throw new Exception("Didn't remove key"); 
					else 
						System.out.println("Deleted");
					
					System.out.print("Finding key 3 using KeyID in secret key...");
					keys = secretRing.findKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[3].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if (keys!=null) 
						throw new Exception("Key has not been deleted!"); 
					else 
						System.out.println("Deleted");
	
					// re add
					System.out.println("Re-adding key 1 (primary + subkey)...");
					secretRing.addKeys(k1_key, k1_uid, k1_secparam);
					System.out.println("Re-dding key 2...");
					secretRing.addKeys(k2_key, k2_uid, k2_secparam);
					System.out.println("Re-dding key 3...");
					secretRing.addKeys(k3_key, k3_uid, k3_secparam);
					
					// reparse keyring (create date will eb different)
					System.out.println("Parsing " + secretkeyring + "...");
					secretKeys = fetchKeys(secretkeyring);
					
					// delete sub
					System.out.print("Key 1 (sub key) using KeyID in secret key...");
					if (secretRing.removeKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[1].getKeyID()), null)!=1)
						throw new Exception("Didn't remove key"); 
					else 
						System.out.println("OK");
	
					System.out.print("Finding key 1 (primary key) using KeyID in secret key...");
					keys = secretRing.findKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[0].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if ((keys==null)||(keys.length!=1)) 
						throw new Exception("Key has been deleted!"); 
					else 
						System.out.print("Found...");
					System.out.print("Comparing...");
					if (compareKeys(true, keys[0].getKeyData().getKey(),k1[0]))
						System.out.println("OK");
					
					System.out.print("Finding key 1 (sub key) using KeyID in secret key...");
					keys = secretRing.findKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[1].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if (keys!=null) 
						throw new Exception("Key has not been deleted!"); 
					else
						System.out.println("Deleted");
					
					System.out.print("Finding key 2 using KeyID in secret key...");
					keys = secretRing.findKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[2].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if ((keys==null)||(keys.length!=1)) 
						throw new Exception("Key has been deleted!"); 
					else 
						System.out.print("Found...");
					System.out.print("Comparing...");
					if (compareKeys(true, keys[0].getKeyData().getKey(),k2[0]))
						System.out.println("OK");
					
					System.out.print("Finding key 3 using KeyID in secret key...");
					keys = secretRing.findKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[3].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if ((keys==null)||(keys.length!=1)) 
						throw new Exception("Key has been deleted!"); 
					else 
						System.out.print("Found...");
					System.out.print("Comparing...");
					if (compareKeys(true, keys[0].getKeyData().getKey(),k3[0]))
						System.out.println("OK");
	
					// delete primary
					System.out.print("Key 1 (primary key) using KeyID in secret key...");
					if (secretRing.removeKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[0].getKeyID()), null)!=1)
					    throw new Exception("Didn't remove 1 keys"); 
					else 
						System.out.println("OK");
					
					System.out.print("Finding key 1 (primary key) using KeyID in secret key...");
					keys = secretRing.findKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[0].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if (keys!=null) 
						throw new Exception("Key has not been deleted!"); 
					else 
						System.out.println("Deleted");
					
					System.out.print("Finding key 1 (sub key) using KeyID in secret key...");
					keys = secretRing.findKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[1].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if (keys!=null) 
						throw new Exception("Key has not been deleted!"); 
					else 
						System.out.println("Deleted");
					
					System.out.print("Finding key 2 using KeyID in secret key...");
					keys = secretRing.findKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[2].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if ((keys==null)||(keys.length!=1)) 
						throw new Exception("Key has been deleted!"); 
					else 
						System.out.print("Found...");
					System.out.print("Comparing...");
					if (compareKeys(true, keys[0].getKeyData().getKey(),k2[0]))
						System.out.println("OK");
					
					System.out.print("Finding key 3 using KeyID in secret key...");
					keys = secretRing.findKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[3].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if ((keys==null)||(keys.length!=1)) 
						throw new Exception("Key has been deleted!"); 
					else 
						System.out.print("Found...");
					System.out.print("Comparing...");
					if (compareKeys(true, keys[0].getKeyData().getKey(),k3[0]))
						System.out.println("OK");
	
					// delete key 2
					System.out.print("Key 2 using KeyID in secret key...");
					if (secretRing.removeKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[2].getKeyID()), null)!=1)
					    throw new Exception("Didn't remove key"); 
					else 
						System.out.println("OK");
					
					System.out.print("Finding key 2 using KeyID in secret key...");
					keys = secretRing.findKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[2].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if (keys!=null) throw new Exception("Key has not been deleted!"); 
					else 
						System.out.println("Deleted");
					
					System.out.print("Finding key 3 using KeyID in secret key...");
					keys = secretRing.findKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[3].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if ((keys==null)||(keys.length!=1)) 
						throw new Exception("Key has been deleted!"); 
					else 
						System.out.print("Found...");
					System.out.print("Comparing...");
					if (compareKeys(true, keys[0].getKeyData().getKey(),k3[0]))
						System.out.println("OK");
					
					// delete key 3
					System.out.print("Key 3 using KeyID in secret key...");
					if (secretRing.removeKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[3].getKeyID()), null)!=1)
					    throw new Exception("Didn't remove key"); 
					else 
						System.out.println("Deleted");
					
					System.out.print("Finding key 3 using KeyID in secret key...");
					keys = secretRing.findKeys(new OpenPGPKeyIDKeyIdentifier(secretKeys[3].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if (keys!=null) 
						throw new Exception("Key has not been deleted!"); 
					else 
						System.out.println("Deleted");
	            }
	
				System.out.print("Testing to see if secret keyring is now empty...");
				OpenPGPPacketInputStream in = new OpenPGPPacketInputStream(new FileInputStream(secretkeyring));
				Packet p = in.readPacket();
				if (p!=null) 
					throw new Exception("Secret keyring still contains packets!"); 
				else 
					System.out.println("OK");
	
				System.out.println("+++ Public Keyring delete Tests +++");
				if (pass == 0) 
				{ // look at uid
					System.out.print("Attempt to delete a non existant key UID in public key...");
					if (publicRing.removeKeys(new OpenPGPStandardKeyIdentifier("Foo".getBytes(), "bar@example.com".getBytes()), null)!=0)
						throw new Exception("removeKeys didn't return 0"); 
					else 
						System.out.println("OK");
					
					// delete primary and seconday
					System.out.print("Key 1 (primary key) using UID in public key...");
					if (publicRing.removeKeys(new OpenPGPStandardKeyIdentifier("Key One".getBytes(), "key1@example.com".getBytes()), null)!=2)
						throw new Exception("Didn't remove 2 keys");
					else
					    System.out.println("OK");
					
					// find
					System.out.print("Finding key 1 using UID in public key...");
					KeyObject[] keys = publicRing.findKeys(new OpenPGPStandardKeyIdentifier("Key One".getBytes(), "key1@example.com".getBytes()), null);
					if (keys!=null) 
						throw new Exception("Key has not been deleted!"); 
					else 
						System.out.println("Deleted");
					
					System.out.print("Finding key 2 using UID in public key...");
					keys = publicRing.findKeys(new OpenPGPStandardKeyIdentifier("Key Two".getBytes(), "key2@example.com".getBytes()), null);
					if ((keys==null)||(keys.length!=1)) 
						throw new Exception("Key has been deleted!"); 
					else 
						System.out.print("Found...");
					System.out.print("Comparing...");
					if (compareKeys(false, keys[0].getKeyData().getKey(),k2[0]))
						System.out.println("OK");
					
					System.out.print("Finding key 3 using UID in public key...");
					keys = publicRing.findKeys(new OpenPGPStandardKeyIdentifier("Key Three".getBytes(), "key3@example.com".getBytes()), new OpenPGPFindKeyParameters("test".getBytes()));
					if ((keys==null)||(keys.length!=1)) 
						throw new Exception("Key has been deleted!"); 
					else 
						System.out.print("Found...");
					System.out.print("Comparing...");
					if (compareKeys(false, keys[0].getKeyData().getKey(),k3[0]))
						System.out.println("OK");
	
					// delete key 2
					System.out.print("Key 2 using UID in public key...");
					if (publicRing.removeKeys(new OpenPGPStandardKeyIdentifier("Key Two".getBytes(), "key2@example.com".getBytes()), null)!=1)
						throw new Exception("Didn't remove key");
					else
						System.out.println("OK");
					
					// find
					System.out.print("Finding key 2 using UID in public key...");
					keys = publicRing.findKeys(new OpenPGPStandardKeyIdentifier("Key Two".getBytes(), "key2@example.com".getBytes()), null);
					if (keys!=null) 
						throw new Exception("Key has not been deleted!"); 
					else 
						System.out.println("Deleted");
					
					System.out.print("Finding key 3 using UID in public key...");
					keys = publicRing.findKeys(new OpenPGPStandardKeyIdentifier("Key Three".getBytes(), "key3@example.com".getBytes()), null);
					if ((keys==null)||(keys.length!=1)) 
						throw new Exception("Key has been deleted!"); 
					else 
						System.out.print("Found...");
					
					System.out.print("Comparing...");
					if (compareKeys(false, keys[0].getKeyData().getKey(),k3[0]))
						System.out.println("OK");
					
					
					// delete key 3
					System.out.print("Key 3 using UID in public key...");
					if (publicRing.removeKeys(new OpenPGPStandardKeyIdentifier("Key Three".getBytes(), "key3@example.com".getBytes()), null)!=1)
					    throw new Exception("Didn't remove key");
					else
					    System.out.println("OK");
					
					// find
					System.out.print("Finding key 3 using UID in public key...");
					keys = publicRing.findKeys(new OpenPGPStandardKeyIdentifier("Key Three".getBytes(), "key3@example.com".getBytes()), null);
					if (keys!=null) 
						throw new Exception("Key has not been deleted!"); 
					else 
						System.out.println("Deleted");
	            }
				if (pass == 1) 
				{ // look at kid
					System.out.println("Parsing " + publickeyring + "...");
					KeyPacket publicKeys[] = fetchKeys(publickeyring);
					
					System.out.print("Attempt to delete a non existant key ID in public key...");
					if (publicRing.removeKeys(new OpenPGPKeyIDKeyIdentifier(kid), null)!=0)
						throw new Exception("removeKeys didn't return 0"); 
					else 
						System.out.println("OK");
					
					                // delete primary and seconday
					System.out.print("Key 1 (primary key) using KeyID in public key...");
					if (publicRing.removeKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[0].getKeyID()), null)!=2)
						throw new Exception("Didn't remove 2 keys"); 
					else 
						System.out.println("OK");
					
					System.out.print("Finding key 1 (primary key) using KeyID in public key...");
					KeyObject[] keys = publicRing.findKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[0].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if (keys!=null) 
						throw new Exception("Key has not been deleted!"); 
					else 
						System.out.println("Deleted");
					
					System.out.print("Finding key 1 (sub key) using KeyID in public key...");
					keys = secretRing.findKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[1].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if (keys!=null) 
						throw new Exception("Key has not been deleted!"); 
					else 
						System.out.println("Deleted");
					
					System.out.print("Finding key 2 using KeyID in public key...");
					keys = publicRing.findKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[2].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if ((keys==null)||(keys.length!=1)) 
						throw new Exception("Key has been deleted!"); 
					else 
						System.out.print("Found...");
					System.out.print("Comparing...");
					if (compareKeys(false, keys[0].getKeyData().getKey(),k2[0]))
						System.out.println("OK");
					
					System.out.print("Finding key 3 using KeyID in public key...");
					keys = publicRing.findKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[3].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if ((keys==null)||(keys.length!=1)) 
						throw new Exception("Key has been deleted!"); 
					else 
						System.out.print("Found...");
					System.out.print("Comparing...");
					if (compareKeys(false, keys[0].getKeyData().getKey(),k3[0]))
						System.out.println("OK");
	
					// delete key 2
					System.out.print("Key 2 using KeyID in public key...");
					if (publicRing.removeKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[2].getKeyID()), null)!=1)
					    throw new Exception("Didn't remove key"); 
					else 
						System.out.println("OK");
					
					System.out.print("Finding key 2 using KeyID in public key...");
					keys = publicRing.findKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[2].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if (keys!=null) 
						throw new Exception("Key has not been deleted!"); 
					else 
						System.out.println("Deleted");
					
					System.out.print("Finding key 3 using KeyID in public key...");
					keys = publicRing.findKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[3].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if ((keys==null)||(keys.length!=1))
						throw new Exception("Key has been deleted!"); 
					else 
						System.out.print("Found...");
					System.out.print("Comparing...");
					if (compareKeys(false, keys[0].getKeyData().getKey(),k3[0]))
						System.out.println("OK");
					
					// delete key 3
					System.out.print("Key 3 using KeyID in public key...");
					if (publicRing.removeKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[3].getKeyID()), null)!=1)
					    throw new Exception("Didn't remove key");
					else 
						System.out.println("OK");
					
					System.out.print("Finding key 3 using KeyID in public key...");
					keys = publicRing.findKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[3].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if (keys!=null) 
						throw new Exception("Key has not been deleted!"); 
					else 
						System.out.println("Deleted");
	
					// re add
					System.out.println("Re-adding key 1 (primary + subkey)...");
					publicRing.addKeys(k1_key, k1_uid, k1_secparam);
					System.out.println("Re-dding key 2...");
					publicRing.addKeys(k2_key, k2_uid, k2_secparam);
					System.out.println("Re-dding key 3...");
					publicRing.addKeys(k3_key, k3_uid, k3_secparam);
					
					// reparse keyring (create date will eb different)
					System.out.println("Parsing " + publickeyring + "...");
					publicKeys = fetchKeys(publickeyring);
	
					// delete sub
					System.out.print("Key 1 (sub key) using KeyID in public key...");
					if (publicRing.removeKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[1].getKeyID()), null)!=1)
						throw new Exception("Didn't remove key"); 
					else 
						System.out.println("OK");
					
					System.out.print("Finding key 1 (primary key) using KeyID in public key...");
					keys = publicRing.findKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[0].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if ((keys==null)||(keys.length!=1)) 
						throw new Exception("Key has been deleted!"); 
					else 
						System.out.print("Found...");
					System.out.print("Comparing...");
					if (compareKeys(false, keys[0].getKeyData().getKey(),k1[0]))
						System.out.println("OK");
					
					System.out.print("Finding key 1 (sub key) using KeyID in public key...");
					keys = publicRing.findKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[1].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if (keys!=null) 
						throw new Exception("Key has not been deleted!"); 
					else 
						System.out.println("Deleted");
					
					System.out.print("Finding key 2 using KeyID in public key...");
					keys = publicRing.findKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[2].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if ((keys==null)||(keys.length!=1)) 
						throw new Exception("Key has been deleted!"); 
					else 
						System.out.print("Found...");
					System.out.print("Comparing...");
					if (compareKeys(false, keys[0].getKeyData().getKey(),k2[0]))
						System.out.println("OK");
					
					System.out.print("Finding key 3 using KeyID in public key...");
					keys = publicRing.findKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[3].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if ((keys==null)||(keys.length!=1)) 
						throw new Exception("Key has been deleted!"); 
					else 
						System.out.print("Found...");
					System.out.print("Comparing...");
					if (compareKeys(false, keys[0].getKeyData().getKey(),k3[0]))
						System.out.println("OK");
	
	                // delete primary
					System.out.print("Key 1 (primary key) using KeyID in public key...");
					if (publicRing.removeKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[0].getKeyID()), null)!=1)
					    throw new Exception("Didn't remove 2 keys"); 
					else 
						System.out.println("OK");
					
					System.out.print("Finding key 1 (primary key) using KeyID in public key...");
					keys = publicRing.findKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[0].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if (keys!=null) 
						throw new Exception("Key has not been deleted!"); 
					else 
						System.out.println("Deleted");
					
					System.out.print("Finding key 1 (sub key) using KeyID in public key...");
					keys = publicRing.findKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[1].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if (keys!=null) 
						throw new Exception("Key has not been deleted!"); 
					else 
						System.out.println("Deleted");
					
					System.out.print("Finding key 2 using KeyID in public key...");
					keys = publicRing.findKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[2].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if ((keys==null)||(keys.length!=1)) 
						throw new Exception("Key has been deleted!"); 
					else 
						System.out.print("Found...");
					System.out.print("Comparing...");
					if (compareKeys(false, keys[0].getKeyData().getKey(),k2[0]))
						System.out.println("OK");
					
					System.out.print("Finding key 3 using KeyID in public key...");
					keys = publicRing.findKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[3].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if ((keys==null)||(keys.length!=1)) 
						throw new Exception("Key has been deleted!");
					else 
						System.out.print("Found...");
					System.out.print("Comparing...");
					if (compareKeys(false, keys[0].getKeyData().getKey(),k3[0]))
						System.out.println("OK");
	
					// delete key 2
					System.out.print("Key 2 using KeyID in public key...");
					if (publicRing.removeKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[2].getKeyID()), null)!=1)
						throw new Exception("Didn't remove key"); 
					else 
						System.out.println("OK");
					
					System.out.print("Finding key 2 using KeyID in public key...");
					keys = publicRing.findKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[2].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if (keys!=null) 
						throw new Exception("Key has not been deleted!"); 
					else 
						System.out.println("Deleted");
					
					System.out.print("Finding key 3 using KeyID in public key...");
					keys = publicRing.findKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[3].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if ((keys==null)||(keys.length!=1)) 
						throw new Exception("Key has been deleted!"); 
					else 
						System.out.print("Found...");
					System.out.print("Comparing...");
					if (compareKeys(false, keys[0].getKeyData().getKey(),k3[0]))
						System.out.println("OK");
	
					// delete key 3
					System.out.print("Key 3 using KeyID in public key...");
					if (publicRing.removeKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[3].getKeyID()), null)!=1)
						throw new Exception("Didn't remove key"); 
					else 
						System.out.println("OK");
					
					System.out.print("Finding key 3 using KeyID in public key...");
					keys = publicRing.findKeys(new OpenPGPKeyIDKeyIdentifier(publicKeys[3].getKeyID()), new OpenPGPFindKeyParameters("test".getBytes()));
					if (keys!=null) 
						throw new Exception("Key has not been deleted!"); 
					else 
						System.out.println("Deleted");
	            }
	
				System.out.print("Testing to see if public keyring is now empty...");
				in = new OpenPGPPacketInputStream(new FileInputStream(publickeyring));
				p = in.readPacket();
				if (p!=null) throw new Exception("Secret keyring still contains packets!"); else System.out.println("OK");
			}
        }
        catch( Exception e )
        {
        	e.printStackTrace();
        	allOK = false;
        }

        return allOK;
    }
    
    public void testOpenPGPKeyrings()
    {
    	assertTrue( doTest() );
    }

}
