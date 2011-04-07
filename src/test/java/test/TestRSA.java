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
import org.bouncycastle.jce.provider.*;
import junit.framework.TestCase;
import java.security.*;
import java.io.*;
import javax.crypto.*;

/**
 * <p>RSA when used to encrypt the session key seems to give inconsistant and unpredictable results.</p>
 * <p>This is a quick test made to establish exactly where the problem with RSA is.</p>
 */
public class TestRSA extends TestCase {
    
    /** Algorithm settings */
    public final int SymmetricAlgorithm = 1; // idea
    public final int PKAlgorithm = 1; // rsa enc & sign
    
    /** <p>Execute the test.</p>
     * <p>You should implement this method with your test. Return true if the test
     * was successful, otherwise return false.</p>
     */
    public void testRSA()
    {
        boolean allOK = true;
        
        Cipher cipher = null;
        Cipher cipher2 = null;

        try
        {
	        System.out.print("Adding BouncyCastleProvider...");    
	        Security.addProvider(new BouncyCastleProvider());
	        System.out.println("Ok.");
	
	        // Generate random key
	        System.out.print("Generating a random session key...");
	        KeyGenerator k = KeyGenerator.getInstance(SymmetricAlgorithmSettings.getCipherText(SymmetricAlgorithm), "BC");
	
	        k.init(SecureRandom.getInstance("SHA1PRNG"));
	        Key key = k.generateKey();
	        System.out.println("Ok.");
	
	        // Generate random rsa keypair
	        System.out.print("Generating RSA keypair...");
	        KeyPairGenerator k2 = KeyPairGenerator.getInstance(PublicKeyAlgorithmSettings.getCipherText(PKAlgorithm), "BC");
	        k2.initialize(PublicKeyAlgorithmSettings.getDefaultKeySize(PKAlgorithm), SecureRandom.getInstance("SHA1PRNG"));
	
	        KeyPair kp = k2.generateKeyPair();
	
	        System.out.println("Ok.");
	
	        // encrypt it
	        System.out.print("Encrypting data ("+PublicKeyAlgorithmSettings.getFullCipherText(PKAlgorithm)+")...");
	        cipher = Cipher.getInstance(PublicKeyAlgorithmSettings.getFullCipherText(PKAlgorithm),"BC");
	        cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
	
	        ByteArrayOutputStream out = new ByteArrayOutputStream();
	        CipherOutputStream cOut = new CipherOutputStream(out, cipher);
	        cOut.write(key.getEncoded());
	        cOut.close();
	        //byte encrypted[] = cipher.doFinal(key.getEncoded());
	
	        System.out.println("Ok.");
	
	        // decrypt it
	        System.out.print("Decrypting data...");   
	        cipher2 = Cipher.getInstance(PublicKeyAlgorithmSettings.getFullCipherText(PKAlgorithm),"BC");
	        cipher2.init(Cipher.DECRYPT_MODE, kp.getPrivate());
	        //byte decrypted[] = cipher.doFinal(encrypted);
	
	        CipherInputStream cIn = new CipherInputStream(new ByteArrayInputStream(out.toByteArray()), cipher2);
	
	        ByteArrayOutputStream buffer2 = new ByteArrayOutputStream();
	        int b;
	        while ( (b = cIn.read())!=-1) 
	            buffer2.write(b);
	
	        System.out.println("Ok.");
	
	        // compare session keys
	        byte decrypted[] = buffer2.toByteArray();
	        System.out.print("Comparing...");  
	        if (decrypted.length!= key.getEncoded().length)
	            throw new Exception("Decrypted data is the wrong length!");
	
	        for (int n=0; n<decrypted.length; n++)
	            if (decrypted[n]!=key.getEncoded()[n]) 
	                throw new Exception("Session keys are different!");
	
	        System.out.println("Ok.");
        }
        catch( Exception e )
        {
        	e.printStackTrace();
        	allOK = false;
        }
        
        // if we got this far then the test should have gone ok
        assertTrue( allOK );
    }
    
}
