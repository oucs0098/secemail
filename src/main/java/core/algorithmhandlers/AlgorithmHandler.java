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

package core.algorithmhandlers;
import core.keyhandlers.KeyHandler;
import core.exceptions.*;
import core.email.*;

/**
 * <p>A comman class defining the base algorithm handler class.</p>
 * <p>All algorithm handler classes inherit off this and must implement the defined abstract methods.</p>
 */
public abstract class AlgorithmHandler {
    
    /** Creates an AlgorithmHander. */
    public AlgorithmHandler() {
    }
    
    
    /**
     * <p>Process an outgoing email.</p>
     * @param encrypt Should the email be encrypted?
     * @param sign Should the email be signed?
     * @param publicKeyStores[] An array of available public key stores.
     * @param privateKeyStores[] An array of availabe private key stores.
     * @param email The email being processed.
     * @param passPhrases A list of passphrases to try unlocking keydata with.
     * @return A new Email object containing the processed data.
     * @throws AlgorithmException if there was an unrecoverable algorithm specific problem.
     * @throws KeyHandlerException if there was an unrecoverable key handler specific problem.
     * @throws ChecksumFailureException if the password you entered was not right.
     * @throws SecretKeyNotFoundException if a key could not be found in a secret keystore.
     * @throws PublicKeyNotFoundException if a key could not be found in a public keystore.
     * @throws EmailDataFormatException if the email was badly formatted and could not be parsed.
     */
    public abstract Email processOutgoingMail(boolean encrypt, boolean sign, KeyHandler [] publicKeyStores, KeyHandler [] privateKeyStores, Email email, PassPhrase passPhrases []) 
        throws AlgorithmException, KeyHandlerException, ChecksumFailureException, SecretKeyNotFoundException, PublicKeyNotFoundException, EmailDataFormatException;
   
    /**
     * <p>Process an incoming email.</p>
     * @param publicKeyStores[] An array of available public key stores.
     * @param privateKeyStores[] An array of availabe private key stores.
     * @param email The email being processed.
     * @param passPhrases A list of passphrases to try unlocking keydata with.
     * @return A new Email object containing the processed data.
     * @throws AlgorithmException if there was an unrecoverable algorithm specific problem.
     * @throws KeyHandlerException if there was an unrecoverable key handler specific problem.
     * @throws ChecksumFailureException if the password you entered was not right.
     * @throws SecretKeyNotFoundException if a key could not be found in a secret keystore.
     * @throws PublicKeyNotFoundException if a key could not be found in a public keystore.
     * @throws EmailDataFormatException if the email was badly formatted and could not be parsed.
     */
    public abstract Email processIncomingMail(KeyHandler [] publicKeyStores, KeyHandler [] privateKeyStores, Email email, PassPhrase passPhrases []) 
        throws AlgorithmException, KeyHandlerException, ChecksumFailureException,  SecretKeyNotFoundException, PublicKeyNotFoundException, EmailDataFormatException;
   
}
