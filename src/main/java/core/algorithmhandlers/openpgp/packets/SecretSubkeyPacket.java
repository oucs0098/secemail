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
import core.algorithmhandlers.keymaterial.*;
import core.exceptions.AlgorithmException;
import core.algorithmhandlers.openpgp.util.S2K;
import java.util.*;
import java.io.*;

/**
 * <p>A class denoting a secret key subkey packet. Identical in all but header to SecretKeyPacket.</p>
 */
public class SecretSubkeyPacket extends SecretKeyPacket {
    
    /** Creates a new instance of SecretSubkeyPacket */
    public SecretSubkeyPacket() {
    }
    
    /** Create a version 3 packet. 
     * @param expiry Number of days this key is valid for, 0 for no expiry.
     * @param keyAlgorithm What public key algorithm is being used.
     * @param symmetricAlg The Symmetric algorithm to use to encrypt the key material.
     * @param s2kSpec The S2K Specifier as defined by the usage convention.
     * @param passPhrase The passphrase to encrypt the key data with.
     * @param keyParams The raw unencrypted key data (public & private) as series of MPIs.
     * @deprecated Use of this constructor can lead to incorrect key IDs being generated when key material is saved in public and secret key rings. 
     * @throws AlgorithmException if the packet could not be created.
     */
    public SecretSubkeyPacket(int expiry, int keyAlgorithm, int symmetricAlg, S2K s2kSpec, byte passPhrase[], AsymmetricAlgorithmParameters keyParams) throws AlgorithmException {
        super(expiry, keyAlgorithm, symmetricAlg, s2kSpec, passPhrase, keyParams);

        setPacketHeader(new PacketHeader(7, false, getPacketHeader().getBodyLength()));
    }
    
    /** Create a version 4 packet. 
     * @param keyAlgorithm What public key algorithm is being used.
     * @param symmetricAlg The Symmetric algorithm to use to encrypt the key material.
     * @param s2kSpec The S2K Specifier as defined by the usage convention.
     * @param passPhrase The passphrase to encrypt the key data with.
     * @param keyParams The raw unencrypted key data (public and private) as series of MPIs.
     * @deprecated Use of this constructor can lead to incorrect key IDs being generated when key material is saved in public and secret key rings. 
     * @throws AlgorithmException if the packet could not be created.
     */
    public SecretSubkeyPacket(int keyAlgorithm, int symmetricAlg, S2K s2kSpec, byte passPhrase[], AsymmetricAlgorithmParameters keyParams) throws AlgorithmException {
        super(keyAlgorithm, symmetricAlg, s2kSpec, passPhrase, keyParams);
        
        setPacketHeader(new PacketHeader(7, false, getPacketHeader().getBodyLength()));
    }
    
    
    
    /** Create a version 3 packet. 
     * @param creationdate A date object representing the time the packet is created. If you are creating a PGP keyring you should use the same Date object for both the public and secret key packets. This will ensure that both halfs of the keypair have the same key ID.
     * @param expiry Number of days this key is valid for, 0 for no expiry.
     * @param keyAlgorithm What public key algorithm is being used.
     * @param symmetricAlg The Symmetric algorithm to use to encrypt the key material.
     * @param s2kSpec The S2K Specifier as defined by the usage convention.
     * @param passPhrase The passphrase to encrypt the key data with.
     * @param keyParams The raw unencrypted key data (public & private) as series of MPIs.
     * @throws AlgorithmException if the packet could not be created.
     */
    public SecretSubkeyPacket(Date creationdate, int expiry, int keyAlgorithm, int symmetricAlg, S2K s2kSpec, byte passPhrase[], AsymmetricAlgorithmParameters keyParams) throws AlgorithmException {
        super(creationdate, expiry, keyAlgorithm, symmetricAlg, s2kSpec, passPhrase, keyParams);

        setPacketHeader(new PacketHeader(7, false, getPacketHeader().getBodyLength()));
    }
    
    /** Create a version 4 packet. 
     * @param creationdate A date object representing the time the packet is created. If you are creating a PGP keyring you should use the same Date object for both the public and secret key packets. This will ensure that both halfs of the keypair have the same key ID.
     * @param keyAlgorithm What public key algorithm is being used.
     * @param symmetricAlg The Symmetric algorithm to use to encrypt the key material.
     * @param s2kSpec The S2K Specifier as defined by the usage convention.
     * @param passPhrase The passphrase to encrypt the key data with.
     * @param keyParams The raw unencrypted key data (public and private) as series of MPIs.
     * @throws AlgorithmException if the packet could not be created.
     */
    public SecretSubkeyPacket(Date creationdate, int keyAlgorithm, int symmetricAlg, S2K s2kSpec, byte passPhrase[], AsymmetricAlgorithmParameters keyParams) throws AlgorithmException {
        super(creationdate, keyAlgorithm, symmetricAlg, s2kSpec, passPhrase, keyParams);
        
        setPacketHeader(new PacketHeader(7, false, getPacketHeader().getBodyLength()));
    }
    
    
}
