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
 * Packet for all byte array based sub key packet.
 */
public abstract class ByteArraySubPacket extends SignatureSubPacket {
    
    /** The string data */
    private byte[] data;
    
    /** Creates a new instance of StringSubPacket */
    public ByteArraySubPacket() {
    }
        
    /** Get the data. */
    public byte[] getData() {
        return data;
    }  
      
    /**
     * <p>Get the data element.</p>
     * <p>Will throw an ArrayIndexOutOfBoundsException class if you try and access an index
     * that does not exist.</p>
     */
    public int getDataElement(int index) {
        return data[index];
    }
    
    /** Return the length of the data array. */
    public int getDataArrayLength() {
        return data.length;
    }
    
    /** Add an element to the end of the array. */
    public void addDataElement(int value) {
        byte tmp[] = new byte[getDataArrayLength()+1];
        
        System.arraycopy(data, 0, tmp, 0, data.length);
        
        setData(tmp);
        
        setDataElement(getDataArrayLength()-1, value);
    }
    
    /** Set an individual data element (for byte data that is an array of octets rather than a string). */
    public void setDataElement(int index, int value) {
        data[index] = (byte)(value & 0xff);
    }
    
    /** Set the data. */
    public void setData(byte value[]) {
        data = value;
    }
  
    /**
     * <p>Construct a packet from a preloaded data array.</p>
     * <p>This method allows the V4SignatureMaterial class to read a full packet in before processing, allowing
     * the read method to better handle unknown packets.</p>
     * @param data[] The full packet.
     * @throws IOException if something went wrong.
     */
    public void decode(byte[] data) throws IOException {
        this.data = data;
    }    
    
    /**
     * <p>Write the packet (with header) out to a byte stream.</p>
     * @throws IOException if something went wrong.
     */
    public void encode(OutputStream out) throws IOException {
        getSubPacketHeader().encode(out);
        
        out.write(data);
    }
    
}
