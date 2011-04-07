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

package core.keyhandlers.keydata;
import core.keyhandlers.KeyData;
import core.algorithmhandlers.openpgp.packets.KeyPacket;
import core.algorithmhandlers.openpgp.packets.UserIDPacket;
import core.exceptions.*;

/**
 * <p>A class representing OpenPGP Key Data.</p>
 * <p>This class is an extension of Keydata that contains extra information about a key than just the key material.</p>
 * <p>Extend this class as necessary (and don't forget to make the appropriate changes in the OpenPGP 
 * key handlers.</p>
 * <p>This class is returned by the findKeys methods in OpenPGP* key handlers.</p>
 */
public class OpenPGPKeyData extends KeyData {
    
    /** Raw key packet data (so we can extract richer information than just key data). */
    private KeyPacket keypacket;
    
    
    /** Creates a new instance of OpenPGPKeyData 
     * @throws AlgorithmException if something went wrong.
     */
    public OpenPGPKeyData(KeyPacket kp) {
        super(kp.getKeyData());
        keypacket = kp;
    }
    
    /** Return the key ID of the key. 
     * @throws AlgorithmException if something went wrong.
     */
    public byte[] getKeyID() throws AlgorithmException {
        return keypacket.getKeyID();
    }
    
    /** Return the fingerprint of the key. 
     * @throws AlgorithmException if something went wrong.
     */
    public byte[] getFingerprint() throws AlgorithmException {
        return keypacket.getFingerprint();
    }
    
    /** Return the keys PK algorithm. */
    public int getAlgorithm() {
        return keypacket.getAlgorithm();
    }
    
    /** Return the underlying OpenPGP key packet. */
    public KeyPacket getKeyPacket() {
        return keypacket;
    }
}
