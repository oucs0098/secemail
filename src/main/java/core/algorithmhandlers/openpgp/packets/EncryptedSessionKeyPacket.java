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

package core.algorithmhandlers.openpgp.packets;
import core.exceptions.AlgorithmException;
import core.exceptions.ChecksumFailureException;
import core.algorithmhandlers.openpgp.util.*;
import org.bouncycastle.jce.provider.*;
import java.security.*;
import javax.crypto.*;
import java.io.*;

/**
 * <p>An abstract class that provides a common interface for all encrypted session key packets.</p>
 */
public abstract class EncryptedSessionKeyPacket extends Packet {

    /** Packet version. */
    private int version;
    
    /** key algorithm used. */
    private int keyAlgorithm;
    
    /** Raw key data, holding the encrypted form of the session key */
    protected byte encryptedSessionKey[];
    
    
    /** Set the version of the packet. */
    protected void setVersion(int ver) {
        version = ver;
    }
    
    /** Get the version of the packet. */
    public int getVersion() {
        return version;
    }
    
    /** Set the key algorithm to use. */
    protected void setKeyAlgorithm(int algorithm) {
        keyAlgorithm = algorithm;
    }
    
    /** Get the public key algorithm being used. */
    public int getKeyAlgorithm() {
        return keyAlgorithm;
    }
    
    /** 
     * <p>Populate the packet with a given session key.</p>
     * <p>The method will encrypt the given session key data using the given public key and store it.</p>
     * @param key The public key to encrypt the session key to.
     * @param sessionkey The session key data together with the alsogithm .
     * @throws AlgorithmException if something went wrong.
     */
    protected abstract void setSessionKey(Key key, SessionKey sessionkey) throws AlgorithmException;
    
    /** 
     * <p>Unpack and decrypt the saved session key using the given private key and return the 
     * session key in its clear form.</p>
     * @throws ChecksumFailureException if the decoded session key failed the checksum.
     * @throws AlgorithmException if something went wrong.
     */
    public abstract SessionKey getSessionKey(Key key) throws AlgorithmException, ChecksumFailureException;
}
