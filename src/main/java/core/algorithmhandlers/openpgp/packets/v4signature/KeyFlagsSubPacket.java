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

package core.algorithmhandlers.openpgp.packets.v4signature;

/**
 * <p>Set the key flags.</p>
 */
public class KeyFlagsSubPacket extends FlagsSubPacket {
    
    /** This key may be used to certify other keys. */
    public static final int MAY_CERTIFY_KEY = 0x01;
    
    /** This key may be used to sign data. */
    public static final int MAY_SIGN_DATA = 0x02;
    
    /** This key may be used to encrypt communications. */
    public static final int MAY_ENCRYPT_COMMS = 0x04;
    
    /** This key may be used to encrypt storage. */
    public static final int MAY_ENCRYPT_STORAGE = 0x08;
    
    /** The private component of this key may have been split by a secret sharing mechanism. */
    public static final int PRIVATE_KEY_SPLIT = 0x10;
    
    /** This key may be used for authentication. */
    public static final int MAY_AUTHENTICATE = 0x20;
    
    /** The private component of this key may be in the possession of more than one person. */
    public static final int PRIVATE_KEY_SHARED = 0x80;
    
    
    /** Creates a new instance of KeyFlagsSubPacket
     * @deprecated We should never assume a fixed size for this subpacket,
     * because the packet should be allowed to grow as time goes on,
     * as defined by the latest OpenPGP Message Format draft, at the time of
     * writing, draft-ietf-openpgp-rfc2440bis-22. PGP, for example, has a 
     * standard size for these flags of 4 bytes.
     */
    public KeyFlagsSubPacket() {
        this(1);
    }
    
    /** Creates a new instance of KeyFlagsSubPacket.
     * @param numflags Number of flag bytes.
     */
    public KeyFlagsSubPacket(int numflags) {
        super(numflags);
        setSubPacketHeader(new SignatureSubPacketHeader(27, false, numflags));
    }
    
    /** Returns true if the MAY_CERTIFY_KEY flag has been set. */
    public boolean getMayCertifyKeyFlag() {
        return getFlag(0, MAY_CERTIFY_KEY);
    }
    
    /** Set the MAY_CERTIFY_KEY flag.
     * @param set Toggle the flag on (true) or off (false).
     */
    public void setMayCertifyKeyFlag(boolean set) {
        setFlag(0, MAY_CERTIFY_KEY, set);
    }
       
    /** Returns true if the MAY_SIGN_DATA flag has been set. */
    public boolean getMaySignDataFlag() {
        return getFlag(0, MAY_SIGN_DATA);
    }
    
    /** Set the MAY_SIGN_DATA flag.
     * @param set Toggle the flag on (true) or off (false).
     */
    public void setMaySignDataFlag(boolean set) {
        setFlag(0, MAY_SIGN_DATA, set);
    }
    
    /** Returns true if the MAY_ENCRYPT_COMMS flag has been set. */
    public boolean getMayEncryptCommsFlag() {
        return getFlag(0, MAY_ENCRYPT_COMMS);
    }
    
    /** Set the MAY_ENCRYPT_COMMS flag.
     * @param set Toggle the flag on (true) or off (false).
     */
    public void setMayEncryptCommsFlag(boolean set) {
        setFlag(0, MAY_ENCRYPT_COMMS, set);
    }
    
    /** Returns true if the MAY_ENCRYPT_STORAGE flag has been set. */
    public boolean getMayEncryptStorageFlag() {
        return getFlag(0, MAY_ENCRYPT_STORAGE);
    }
    
    /** Set the MAY_ENCRYPT_STORAGE flag.
     * @param set Toggle the flag on (true) or off (false).
     */
    public void setMayEncryptStorageFlag(boolean set) {
        setFlag(0, MAY_ENCRYPT_STORAGE, set);
    }
    
    /** Returns true if the MAY_AUTHENTICATE flag has been set. */
    public boolean getMayAuthenticateFlag() {
        return getFlag(0, MAY_AUTHENTICATE);
    }
    
    /** Set the MAY_AUTHENTICATE flag.
     * @param set Toggle the flag on (true) or off (false).
     */
    public void setMayAuthenticateFlag(boolean set) {
        setFlag(0, MAY_AUTHENTICATE, set);
    }
    
    /** Returns true if the PRIVATE_KEY_SPLIT flag has been set. */
    public boolean getPrivateKeySplitFlag() {
        return getFlag(0, PRIVATE_KEY_SPLIT);
    }
    
    /** Set the PRIVATE_KEY_SPLIT flag.
     * @param set Toggle the flag on (true) or off (false).
     */
    public void setPrivateKeySplitFlag(boolean set) {
        setFlag(0, PRIVATE_KEY_SPLIT, set);
    }
    
    /** Returns true if the PRIVATE_KEY_SHARED flag has been set. */
    public boolean getPrivateKeySharedFlag() {
        return getFlag(0, PRIVATE_KEY_SHARED);
    }
    
    /** Set the PRIVATE_KEY_SHARED flag.
     * @param set Toggle the flag on (true) or off (false).
     */
    public void setPrivateKeySharedFlag(boolean set) {
        setFlag(0, PRIVATE_KEY_SHARED, set);
    }
}
