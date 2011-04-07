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

package core;
import core.interfaces.*;
import core.algorithmhandlers.*;
import core.keyhandlers.KeyHandler;
import java.security.PrivateKey;
import java.util.Vector;
import javax.swing.JOptionPane;


/**
 * <p>Superclass describing a valid email pipe.</p>
 */
public abstract class EmailPipe extends Thread {
  
    /** The object that handles encryption & signing. */
    protected AlgorithmHandler algorithm;
    /** A list of key handlers to look for private keys in */
    protected KeyHandler[] secretKeyHandlers; 
    /** A list of key handlers to look for public keys in */
    protected KeyHandler[] publicKeyHandlers; 
    /** <p>A list of passphrases.</p> 
     * <p>When the algorithm handler needs a password it will try every code cached in this list. 
     * If no password works or the list is empty an exception is thrown and the pipe prompts the user
     * for a new password.</p>
     */
    protected PassPhrase[] passPhrases;
    
    
    /** A string to prefix status output with. */
    private String pipeStatusPrefix = "";

    /** Is the thread main loop running or not? */
    private boolean isRunning;

    /** Generic pipe construction. */
    public EmailPipe() {
        setRunning(false);
    }

    /** Toggle the running flag */
    protected void setRunning(boolean running) {
        isRunning = running;
    }

    /** Get the status of the running flag */
    public boolean getRunning() {
        return isRunning;
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

    /** <p>Set the message prefix text.</p>
     * <p>This text is displayed before the message when using printStatus or printErr. </p>
     * @see #printStatus(String)
     * @see #printErr(String)
     */
    protected void setPipeStatusPrefix(String prefix) {
        pipeStatusPrefix = new String(prefix);
    }

    /** <p>Get the message prefix text.</p>
     * <p>This text is displayed before the message when using printStatus or printErr. </p>
     * @see #printStatus(String)
     * @see #printErr(String)
     */
    public String getPipeStatusPrefix() {
        return pipeStatusPrefix;
    }

    /** Print a nice status message to the console. */
    protected void printStatus(String status) {
        System.out.println(pipeStatusPrefix + ": " + status);
    }

    /** Print a nice error message to the console and display a popup message. */
    protected void printErr(String status) {
        System.err.println(pipeStatusPrefix + ": " + status);
        
        // Display a popup dialog with error in it
        JOptionPane.showMessageDialog(null, status, pipeStatusPrefix, JOptionPane.ERROR_MESSAGE);
    }

    /** <p>Stop the pipe.</p>
     * <p>Stops the email pipe. </p>
     * <p>When stopping the protocolServer object stopPipe will handle any exception generated as a result of the socket
     * being in an accept state.<p>
     */
    public abstract void stopPipe();

    /**
     * <p>Princible run loop.</p>
     * <p>Listens for client connection and negotiates transfer of email.</p>
     * <p>Implement this with your main mail handling loop.</p>
     */
    public abstract void run();
}
