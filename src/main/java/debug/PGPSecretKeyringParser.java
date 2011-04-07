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

package debug;
import java.security.*;
import java.math.BigInteger;
import org.bouncycastle.jce.provider.*;
import core.algorithmhandlers.openpgp.*;
import core.algorithmhandlers.openpgp.packets.*;
import core.algorithmhandlers.keymaterial.*;
import core.algorithmhandlers.openpgp.util.*;
import java.io.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.spec.RSAPublicKeySpec;

/**
 * <p>Parse a secret keyring.</p>
 * <p>This class will read a given secret keyring file and when a key is found will prompt the user to enter
 * a pass phrase. It will then attempt to decrypt and display the key material.</p>
 * <p>This class really serves only to verify compatibility with existing PGP implementations and verify that
 * this PGP implementation can import keys written by other pgp implementations (in particular NAPGP).
 */
public class PGPSecretKeyringParser {
    
    /** Version number */
    private static String version = "v1.0";
    
    /** Creates a new instance of PGPSecretKeyringParser */
    public PGPSecretKeyringParser() {
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        debug.Debug.setLevel(1); // set default debug verbosity
        
        if (args.length == 0) {
            System.out.println("PGPSecretKeyringParser - PGP Secret key viewer " + version + " : By Marcus Povey");
            System.out.println();
            System.out.println("Usage: java test.PGPSecretKeyringParser <filename>");
        } else {
            try {
                
                  // generate and write demo packet.
                System.out.println("Adding Bouncy Castle JCE provider...");
                Security.addProvider(new BouncyCastleProvider());

                System.out.println("Opening packet stream to "+args[0]+"...");
                OpenPGPPacketInputStream in = new OpenPGPPacketInputStream(new FileInputStream(args[0]));

                System.out.println("Reading packet stream...");
                int n = 1;
                
                Packet p = null;
                do {

                    p = in.readPacket();

                    if (p!=null) {
                        System.out.print("Packet " + n +": ");
                        System.out.print("Type " + p.getPacketHeader().getType() );
                        if (p.getPacketHeader().isNewFormat())
                            System.out.print(" (New Format),");
                        else
                            System.out.print(",");

                        System.out.print(" Body length " + p.getPacketHeader().getBodyLength());
                        System.out.println();
                        
                        // handle secret key
                        if (p instanceof SecretKeyPacket) {
                            SecretKeyPacket skp = (SecretKeyPacket)p;
                            
                            System.out.println("Secret key packet detected! ");
                            
                            if (/*(skp.getVersion() == 4) && */(PublicKeyAlgorithmSettings.isRSA(skp.getAlgorithm()))) {

                                // key ID
                                System.out.print("KeyID: 0x");
                                debug.Debug.hexDump(1,skp.getKeyID());

                                // fingerprint
                                System.out.print("Fingerprint: 0x");
                                debug.Debug.hexDump(1,skp.getFingerprint());

                                // prompt for passphrase
                                System.out.print("Enter passphrase for decryption: ");

                                String inputLine;       
                                BufferedReader br = new BufferedReader(new InputStreamReader(System.in));    

                                inputLine = br.readLine(); 

                                // decrypt and output key material
                                skp.decryptKeyData(inputLine.getBytes());

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
                            } else {
                                System.out.println("Sorry, only v4 keys are currently supported...");
                            }
                        }
                    }
                    
                    n++;
                } while (p!=null);
                
                System.out.println("Closing stream...");
                in.close();
            } catch (Exception e) {
                System.err.println(e.getMessage());
                e.printStackTrace();
            }
        }
    }
    
}
