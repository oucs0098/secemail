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
import java.util.Date;
import java.io.*;

/**
 * <p>A sub packet that stores a time.</p>
 * <p>This class is implemented by all time related sub packets eg, SignatureCreationTimeSubPacket &
 * KeyExpirationTimeSubPacket.</p>
 */
public abstract class TimeSubPacket extends SignatureSubPacket {
    
    /** The time data. */
    private long time;
    
    /** Creates a new instance of TimeSubPacket */
    public TimeSubPacket() {
    }
    
    /** Get the time as a PGP compatible value */
    public long getTimeLong() {
        return time;
    }
    
    /** Set the time as a PGP compatible value */
    protected void setTime(long date) {
        time = date;
    }
    
    /** Get the time as a date object */
    public Date getTime() {
        return new Date(time * 1000);
    }
    
    /** Set the time as a date object */
    protected void setTime(Date date) {
        setTime(date.getTime() / 1000);
    }
    
    /**
     * <p>Write the packet (with header) out to a byte stream.</p>
     * @throws IOException if something went wrong.
     */
    public void encode(OutputStream out) throws IOException {
        getSubPacketHeader().encode(out);
        
        out.write((int)((getTimeLong() >> 24) & 0xFF));
        out.write((int)((getTimeLong() >> 16) & 0xFF));
        out.write((int)((getTimeLong() >> 8) & 0xFF));
        out.write((int)((getTimeLong() >> 0) & 0xFF));
    }
    
    /**
     * <p>Construct a packet from a preloaded data array.</p>
     * <p>This method allows the V4SignatureMaterial class to read a full packet in before processing, allowing
     * the read method to better handle unknown packets.</p>
     * @param data[] The full packet.
     * @throws IOException if something went wrong.
     */
    public void decode(byte[] data) throws IOException {
        ByteArrayInputStream in = new ByteArrayInputStream(data);
        
        long date = ( ((in.read() & 0xFFl) << 24) 
                    | ((in.read() & 0xFFl) << 16)
                    | ((in.read() & 0xFFl) <<  8)
                    | ((in.read() & 0xFFl) ));
        setTime(date);
    }

}
