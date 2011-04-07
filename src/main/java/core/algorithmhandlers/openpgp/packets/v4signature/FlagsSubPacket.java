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
 * <p>A root class for all flag sub packets.</p>
 */
public abstract class FlagsSubPacket extends ByteArraySubPacket {
    
    /** Creates a new instance of FlagsSubPacket */
    public FlagsSubPacket() {
        
    }
    
    /** Creates a new instance of FlagsSubPacket.
     * @param numflags Number of flag bytes.
     */
    public FlagsSubPacket(int numflags) {
        byte [] tmp = new byte[numflags];
        
        for (int n = 0; n < numflags; n++) 
            tmp[n] = 0;
        
        setData(tmp);
    }
    
    /** Get the value of a given flag. 
     * @param location The location of the flag to query, 0 - n-1.
     * @param flag The flag to query.
     */
    public boolean getFlag(int location, int flag) {
        return (getDataElement(location) & flag) != 0;
    }
    
    /** Set the value of a given flag.
     * @param location The location of the flag to set, 0 - n-1.
     * @param flag The flag to set.
     * @param set Toggle the flag on (true) or off (false)
     */
    public void setFlag(int location, int flag, boolean set) {
        if (set) {
            setDataElement(location, getDataElement(location) | flag);
        } else {
            setDataElement(location, getDataElement(location) & ~flag);
        }
    }
}
