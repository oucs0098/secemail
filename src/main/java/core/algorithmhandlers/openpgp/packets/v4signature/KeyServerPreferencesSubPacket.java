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
 * <p>Key server flags.</p>
 */
public class KeyServerPreferencesSubPacket extends FlagsSubPacket {
    
    /** The key holder requests that this key only be modified or updated by the key holder or an administrator of the key server. */
    public static final int NO_MODIFY = 0x80;
    
    /** Creates a new instance of KeyServerPreferencesSubPacket */
    public KeyServerPreferencesSubPacket() {
    }
    
    /** Creates a new instance of KeyServerPreferencesSubPacket 
     * @param numflags Number of flag bytes.
     */
    public KeyServerPreferencesSubPacket(int numflags) {
        super(numflags);
        setSubPacketHeader(new SignatureSubPacketHeader(23, false, numflags));
    }
    
    /** Returns true if the NO_MODIFY flag has been set. */
    public boolean getNoModifyFlag() {
        return getFlag(0, NO_MODIFY);
    }
    
    /** Set the NO_MODIFY flag.
     * @param set Toggle the flag on (true) or off (false).
     */
    public void setNoModifyFlag(boolean set) {
        setFlag(0, NO_MODIFY, set);
    }
}
