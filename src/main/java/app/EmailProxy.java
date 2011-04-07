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

package app;
import core.*;
import core.exceptions.*;
import core.protocolhandlers.*;
import core.algorithmhandlers.*;
import core.algorithmhandlers.openpgp.util.*;
import core.keyhandlers.*;
import system.*;
import ui.*;
import java.io.*;
import java.util.*;
import java.security.*;
import org.bouncycastle.jce.provider.*;

/**
 * <p>This is the main proxy application. Running this will start the proxy server. </p>
 * @author Marcus Povey
*/
public class EmailProxy extends Thread
{
    /** Incoming email pipe */
    private IncomingEmailPipe incomingPipe;
    /** Outgoing email pipe */
    private OutgoingEmailPipe outgoingPipe;

    /** Configuration information */
    private ConfigurationData configData;

    /**
     * <p>The constructor.</p>
     * <p>Starts the proxy server threads and sets up the gui.</p>
     * @param configFile The path and filename of the config file where the proxy loads and saves extra configuration information.
     */
    public EmailProxy(String configFile) {

            // Register cleanup handler
            Runtime.getRuntime().addShutdownHook(this);

            // Load settings
            try {
                configData = new ConfigurationData(configFile);
            } catch (IOException e) {
                System.err.println("Could not load configuration data : " + e.getMessage());
                System.exit(0);
            }

            // Starting GUI & redirecting stdout & stderr if hideGUI is false
            MainWindow mainWindow = new MainWindow(configData);
            StatusOutputStream statusWindow = new StatusOutputStream(mainWindow);
            PrintStream stdOut = new PrintStream(statusWindow);
            PrintStream stdErr = new PrintStream(statusWindow);
            System.setOut(stdOut);
            System.setErr(stdErr);
            mainWindow.show();
            
            // display a short copyright message
            displayCopyrightMessageShort();

            // Construct pipes and start server threads
            try {
                
                KeyHandler publicKeyManagers[] = null;
                KeyHandler secretKeyManagers[] = null;
                
                // Create Algorithm Handler
                    AlgorithmHandler algorithmHandler = null;
                    if (configData.getSetting("algorithm","openpgp").compareToIgnoreCase("openpgp")==0) {
                        
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
                        
                        algorithmHandler = new OpenPGPHandler(
                            symmetricAlgorithm
                        );
                        
                        
                        // Load key manager lists
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
                    } 
                
                // Create incoming email pipe

                    // Create client side protocol handler
                        POP3Handler pop3 = new POP3Handler();
                        POP3Handler serverSide = null;
                        pop3.initServerConnection(Integer.parseInt(configData.getSetting("proxyserver.incoming.port","110")));

                    // Create server side protocol handler
                        if (configData.getSetting("mailserver.incoming.protocol.used","POP3").compareToIgnoreCase("POP3")==0) {
                            // server side is pop3.. pop3 server is always defined, so i just have to configure it
                            serverSide = pop3;
                            serverSide.initClientConnection(
                                configData.getSetting("mailserver.incoming.address",""),
                                Integer.parseInt(configData.getSetting("mailserver.incoming.port","110"))
                            );
                        }
                        
                    // create a new passphrase dialog generator for the incoming pipe's use
                        PassPhraseRequester ppr = new PassPhraseDialogGenerator();

                    incomingPipe = new IncomingEmailPipe(pop3,algorithmHandler,secretKeyManagers,ppr,publicKeyManagers,serverSide);


               // Create outgoing SMTP pipe
                    SMTPHandler smtp = new SMTPHandler();
                    smtp.initClientConnection(
                        configData.getSetting("mailserver.outgoing.address",""),
                        Integer.parseInt(configData.getSetting("mailserver.outgoing.port","25")));
                    smtp.initServerConnection(Integer.parseInt(configData.getSetting("proxyserver.outgoing.port","25")));
                    
                    // create a new passphrase dialog generator for the outgoing pipe's use
                        ppr = new PassPhraseDialogGenerator();

                    outgoingPipe = new OutgoingEmailPipe(smtp,algorithmHandler,secretKeyManagers,ppr,publicKeyManagers,smtp,
                        (configData.getSetting("openpgp.encryptalloutgoingemail","1").compareTo("1")==0),
                        (configData.getSetting("openpgp.signalloutgoingemail","1").compareTo("1")==0));

            } catch (Exception e) {
                System.err.println("Could not create email pipes : " + e.getMessage());
                e.printStackTrace(System.err);
            }
            
            // Start the pipes
                incomingPipe.start();
                outgoingPipe.start();

    }

    /** The shutdown hook that will be run by the Java VM when the proxy server exits. */
    public void run() {
            if (incomingPipe!=null) incomingPipe.stopPipe();
            if (outgoingPipe!=null) outgoingPipe.stopPipe();
    }
    
    /** Display a copyright message (as recommended in the GPL license). */
    protected static void displayCopyrightMessageShort() {
        System.out.println("Secure Email Proxy v" + app.AppVersionInfo.version);
        System.out.println("(C) Copyright 2002/3, Oxford Brookes University Secure Email Project");
        System.out.println("This project comes with ABSOLUTELY NO WARRANTY. This is free");
        System.out.println("software, and you are welcome to redistribute it under certain");
        System.out.println("conditions. See GPL.txt for details.");
        System.out.println();
    }
    
    /** <p>Display the full copyright message (as recommended in the GPL license).</p> 
     * <p>This file data is loaded from "/res/gpl.txt".</p>
     */
    protected static void displayCopyrightMessage() {
        
        try {
            Object c = new Object();
            BufferedReader r = new BufferedReader(new InputStreamReader(c.getClass().getResourceAsStream("/res/gpl.txt")));

            while (r.ready()) {
                System.out.println(r.readLine());
            }

            r.close();
        } catch (Exception e) {
            System.err.println("Could not load copyright data.");
        }
    }

    /** The main function. Reads command line and starts the email proxy. */
    public static void main(String args[]) {
        String configFile = "EmailProxy.dat"; // default config file
        
        for (int n = 0; n < args.length; n++) {
            if (args[n].compareToIgnoreCase("-f")==0) {
                if (n+1 < args.length)
                    configFile = args[n+1];
            }
            
            if (args[n].compareToIgnoreCase("/c")==0) {
                displayCopyrightMessage();
                System.exit(0);
            }

            if (args[n].compareToIgnoreCase("/?")==0) {
               System.out.println("---------------------------------------------------------------");
               System.out.println("Secure Email Proxy v" + app.AppVersionInfo.version);
               System.out.println("(C) Copyright 2003/3, Oxford Brookes University Secure Email Project");
               System.out.println(app.AppVersionInfo.website);
               System.out.println("---------------------------------------------------------------");
               System.out.println("");
               System.out.println("Usage : ");
               System.out.println("        java app.EmailProxy [options] [switches]");
               System.out.println("");
               System.out.println("Options :");
               System.out.println("        -f \"configfile\" - The path and filename of the configuration file. ");
               System.out.println("                          This should be an absolute path, since the");
               System.out.println("                          working directory is undefined on some platforms.");
               System.out.println("");
               System.out.println("                  Default \"EmailProxy.rc\"");
               System.out.println("");
               System.out.println("Switches :");
               System.out.println("         /? - This page.");
               System.out.println("         /c - Display copyright information.");
               System.out.println("");
               System.exit(0);
            }

        }

	new EmailProxy(configFile);
    }
}