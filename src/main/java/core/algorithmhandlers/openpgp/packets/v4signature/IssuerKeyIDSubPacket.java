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
import java.io.*;

/**
 * A sub packet that holds the key id of a sub key packet.
 */
public class IssuerKeyIDSubPacket extends SignatureSubPacket {
    
    /** Key ID of the signer. */
    private byte keyID[];
    
    /** Creates a new instance of IssuerKeyID */
    public IssuerKeyIDSubPacket() {
    }
    
    /** Creates a new instance of IssuerKeyID and sets the key id */
    public IssuerKeyIDSubPacket(byte[] id) {
        keyID = id;
        setSubPacketHeader(new SignatureSubPacketHeader(16, false, 8));
    }
    
    /** Return the key ID */
    public byte[] getKeyID() {
        return keyID;
    }
    
    /**
     * <p>Write the packet (with header) out to a byte stream.</p>
     * @throws IOException if something went wrong.
     */
    public void encode(OutputStream out) throws IOException {
        getSubPacketHeader().encode(out);
        out.write(keyID);
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
        
        keyID = new byte[8];
        in.read(keyID);
    }
    
}
