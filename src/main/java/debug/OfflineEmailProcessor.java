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
import core.keyhandlers.KeyHandler;
import core.algorithmhandlers.*;
import core.algorithmhandlers.openpgp.util.*;
import core.exceptions.*;
import core.email.*;
import java.io.*;
import java.security.*;
import java.math.BigInteger;
import org.bouncycastle.jce.provider.*;
import core.keyhandlers.*;
import core.exceptions.*;
import core.algorithmhandlers.openpgp.*;
import core.algorithmhandlers.openpgp.packets.*;
import core.algorithmhandlers.openpgp.packets.v4signature.*;
import core.algorithmhandlers.openpgp.util.*;
import core.algorithmhandlers.keymaterial.*;
import core.keyhandlers.parameters.*;
import core.keyhandlers.identifiers.*;
import java.io.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.spec.*;
import system.*;

/**
 * <p>A program for reading and decrypting email offline.</p>
 * <p>This process will read an email (complete with headers) from file, process it and output the result to stdout. Mail parsing info is written to stderr.</p>
 * <p>Use to process files offline or for testing.</p>
 */
public class OfflineEmailProcessor {
    
    /** Version number */
    private static String version = "v1.0";
    private PassPhrase[] passPhrases;
    private OpenPGPHandler h;
    
    /** Creates a new instance of OfflineEmailProcessor */
    public OfflineEmailProcessor(String configFile, String file) throws Exception {
        
        // load config
        ConfigurationData configData = new ConfigurationData(configFile);
        Security.addProvider(new BouncyCastleProvider());

        String symAlg = configData.getSetting("openpgp.symmetricalgorithm.used","IDEA");
        int symmetricAlgorithm = 0;

        // load defaults
        if ("IDEA".compareToIgnoreCase(symAlg)==0) {
            symmetricAlgorithm = SymmetricAlgorithmSettings.IDEA;
        } else if ("CAST5".compareToIgnoreCase(symAlg)==0) {
            symmetricAlgorithm = SymmetricAlgorithmSettings.CAST5;
        } else if ("3DES".compareToIgnoreCase(symAlg)==0) {
            symmetricAlgorithm = SymmetricAlgorithmSettings.TRIPLEDES;
        } else {
            System.err.println("Symmetric algorithm '"+symAlg+"' is not supported.");
        }

        // Load key manager lists
            KeyHandler publicKeyManagers[] = null;
            KeyHandler secretKeyManagers[] = null;
            Vector pubkm = new Vector();
            Vector seckm = new Vector();

            // load base key managers
                pubkm.add(new OpenPGPPublicKeyring(configData.getSetting("keymanager.openpgp.primary.pubring","pubring.pgp") , null));
                seckm.add(new OpenPGPPublicKeyring(configData.getSetting("keymanager.openpgp.primary.secring","secring.pgp") , null));

            // load extra key managers
                KeyHandler [] tmp = KeyHandler.loadKeysourceList(configData, "keymanager.openpgp.publiclist.");
                if (tmp!=null) {
                    for (int n = 0; n < tmp.length; n++)
                        pubkm.add(tmp[n]);
                }

                tmp = KeyHandler.loadKeysourceList(configData, "keymanager.openpgp.secretlist.");
                if (tmp!=null) {
                    for (int n = 0; n < tmp.length; n++)
                        seckm.add(tmp[n]);
                }

            // store in arrays
                publicKeyManagers = new KeyHandler[pubkm.size()];
                for (int n=0; n<publicKeyManagers.length; n++)
                    publicKeyManagers[n] = (KeyHandler)pubkm.elementAt(n);

                secretKeyManagers = new KeyHandler[seckm.size()];
                for (int n=0; n<secretKeyManagers.length; n++)
                    secretKeyManagers[n] = (KeyHandler)seckm.elementAt(n);

        // create email processor
        h = new OpenPGPHandler(symmetricAlgorithm);

        // process email

        FileInputStream in = new FileInputStream(file);
        byte [] email1_dat = new byte[in.available()];
        in.read(email1_dat);
        in.close();

        System.err.println("Parsing...");
        Email email1 = new Email(email1_dat);

        System.err.println("Processing...");

        boolean retry;

        do {

            retry = false;

            try {
                email1 = h.processIncomingMail(publicKeyManagers, secretKeyManagers, email1, passPhrases);
            } catch (ChecksumFailureException cfe) {

                retry = true;

                System.err.print("Passphrase required: ");
                
                String inputLine;       
                BufferedReader br = new BufferedReader(new InputStreamReader(System.in));    

                inputLine = br.readLine(); 
                PassPhrase p = new PassPhrase(inputLine.getBytes());
                addPassphrase(p);
            }
        } while (retry);

        System.out.println(new String(email1.getBytes()));

    }
    
    public void processEmail(Email email1) throws Exception {
        System.err.println("Analysing...");

            if (email1.isMultipartBody())
                System.err.println("Email has a MULTIPART body");
        
            EmailHeader [] e = email1.getHeader("from");
            System.err.println("Email is from : "+ e[0].getTagValue());
            e = email1.getHeader("to");
            System.err.println("Email is to : "+ e[0].getTagValue());
            e = email1.getHeader("subject");
            System.err.println("Email subject is : "+ e[0].getTagValue());
            EmailHeader [] headers1 = email1.getHeaderArray();
            
            System.err.println("Reading recipients using a different method : ");
            String [] to = email1.getRecipients();
            for (int n=0; n<to.length; n++) 
                System.err.println(to[n]);

            System.err.println("Full headers are....");
            for (int n = 0; n < headers1.length; n++) 
                System.err.println("-- " + headers1[n].toString());
            
            EmailAttachment [] attachments = email1.getAttachments();
            if (attachments!=null) {
                System.err.println("Email has the following attachments...");    
                for (int n = 0; n < attachments.length; n++)
                    System.err.println("File : " + attachments[n].getFilename());
            }

        System.err.println("Modifying subject...");    
            email1.setHeader("subject", "This is a modified subject header for email 1");
        System.err.println("Adding a new header...");    
            email1.setHeader("foo", "This is an extra tag");

            e = email1.getHeader("subject");
            System.err.println("Email subject is now : "+ e[0].getTagValue());
            e = email1.getHeader("foo");
            System.err.println("Foo is : "+ e[0].getTagValue());
  
    }
    
    /** Add passphrase to list of passphrases. */
    public void addPassphrase(PassPhrase passphrase) {
        
        Vector v = new Vector();
        
        if (passPhrases!=null) {
            for (int n = 0; n < passPhrases.length; n++) {
                v.add(passPhrases[n]);
            }
        }
        
        v.add(passphrase);
        
        PassPhrase [] tmp = new PassPhrase[v.size()];
        for (int n = 0; n < v.size(); n++) 
            tmp[n] = (PassPhrase)v.elementAt(n);
        
        passPhrases = tmp;                          
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
         
        try {
            String configFile = "EmailProxy.dat"; // default config file
            String file = "";

            if (args.length < 2) {
                System.out.println("OfflineEmailProcessor - Offline Email file processor " + version + " : By Marcus Povey");
                System.out.println();
                System.out.println("Usage: java debug.OfflineEmailProcessor [-f config file] -e <savedemailfile> ");
            } else {
                for (int n = 0; n < args.length; n++) {
                    if (args[n].compareToIgnoreCase("-f")==0) {
                        if (n+1 < args.length)
                            configFile = args[n+1];
                    }

                    if (args[n].compareToIgnoreCase("-e")==0) {
                        if (n+1 < args.length)
                            file = args[n+1];
                    }
                }

                OfflineEmailProcessor p = new OfflineEmailProcessor(configFile, file);
            }  
        
        } catch (Exception e) {
            System.err.println(e.getMessage());
            e.printStackTrace();
        }
    }
    
}


