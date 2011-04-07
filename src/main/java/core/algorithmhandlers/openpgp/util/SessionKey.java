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

package core.algorithmhandlers.openpgp.util;
import core.exceptions.AlgorithmException;
import java.security.*;
import javax.crypto.*;
import java.lang.Exception;

/**
 * <p>A class that contains session key information.</p>
 * <p>This class contains raw session key data, together with details about which symetric algorithm
 * to use with this session key.</p>
 * <p>No format checking is performed on the key data, therefore it is up to the calling function to ensure
 * data is in the correct format for the algorithm being used.</p>
 */
public class SessionKey {

    /** A variable to identify the symetric key algorithm to use with the session key. */
    private int algorithm;
    /** The session key data. */
    private byte sessionkey[];

    /** Creates a new instance of SessionKey.
     * @param alg The algorithm to use with the session key.
     * @param key[] The session key data.
     */
    public SessionKey(int alg, byte key[]) {
        setAlgorithm(alg);
        setSessionKey(key);
    }
    
    /** <p>Create a new instance of SessionKey.</p>
     * <p>This constructor will automatically generate a session key for the given algorithm.</p>
     * @param alg The symmetric algorithm to use.
     * @throws AlgorithmException if the given algorithm is not supported or if something went wrong.
     */
    public SessionKey(int alg) throws AlgorithmException {
        try {
            // generate session key
            KeyGenerator k = KeyGenerator.getInstance(SymmetricAlgorithmSettings.getCipherText(alg), "BC");
            k.init(SecureRandom.getInstance("SHA1PRNG"));
            Key key = k.generateKey();

            setAlgorithm(alg);
            setSessionKey(key.getEncoded());
        } catch (Exception e) {
            throw new AlgorithmException(e.getMessage());
        }
    }

    /** Set the session key. */
    public void setSessionKey(byte data[]) {
        sessionkey = data;
    }

    /** Get the registered session key. */
    public byte[] getSessionKey() {
        return sessionkey;
    }

    /** Set the algorithm to use with the session key. */
    public void setAlgorithm(int alg) {
        algorithm = alg;
    }

    /** Get the algorithm to use with the session key. */
    public int getAlgorithm() {
        return algorithm;
    }
}
