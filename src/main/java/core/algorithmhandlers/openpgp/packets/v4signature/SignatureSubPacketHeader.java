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
 * <p>A header class for use with signature sub packets.</p>
 */
public class SignatureSubPacketHeader {
    
    /** Packet type. */
    private int type;

    /** The body length. */
    private long bodylength;
    
    /** Is the packet critical? */
    private boolean critical;
    
    /** Creates a new instance of SignatureSubPacketHeader from a stream. */
    public SignatureSubPacketHeader(int packetType, boolean isCritical, long length) {
        type = packetType;
        critical = isCritical;
        bodylength = length;
    }
    
    /** Creates a new instance of SignatureSubPacketHeader from a stream. */
    public SignatureSubPacketHeader(InputStream in) throws IOException {
        decode(in);
    }
    
    /** Get the type of packet.*/
    public int getType() {
        return type;
    }
    
    /** Get the length of the body. */
    public long getBodyLength() {
        return bodylength;
    }
    
    /** Is the packet critical? */
    public boolean isCritical() {
        return critical;
    }
    
    /** 
     * Encode the packet header out to an output stream.
     * @param out Output stream to use.
     * @throws IOException if something went wrong.
     */ 
    public void encode(OutputStream out) throws IOException {

        long fullLength = bodylength+1;
        
        if ( fullLength < 192 ) {
            out.write((byte)(fullLength & 0xff));
        } else if (fullLength < 16320) {
            out.write((byte)(((fullLength - 192) >> 8) + 192));
            out.write((byte)(fullLength - 192));
        } else if (fullLength < 4294967296L) {
            out.write(255); 
            out.write((byte)(fullLength >> 24));
            out.write((byte)(fullLength >> 16));
            out.write((byte)(fullLength >> 8));
            out.write((byte)(fullLength));
        }
           
        // write type and critical flag
        out.write((critical ? ((0x80 | getType()) & 0xff ) : (getType())) & 0xff);
    }
    
    /** 
     * Decode the packet header from an input stream.
     * @param in Input stream to use.
     * @throws IOException if something went wrong.
     */ 
    public void decode(InputStream in) throws IOException {
        // read length
        int lengthType = in.read();
        if (lengthType < 192) {
            bodylength = lengthType;
        } else if ((lengthType >= 192) && (lengthType < 255)) {
            bodylength = ((lengthType - 192) << 8) + (in.read() & 0xff) + 192;
        } else if(lengthType == 255) {
            bodylength = (
                ( (in.read() & 0xff) << 24) +
                ( (in.read() & 0xff) << 16) +
                ( (in.read() & 0xff) << 8) +
                ( in.read() & 0xff )
            );
        }
        
        // adjust because below byte is actually considered as part of the body by NAPGP
        bodylength--;

        // read type & critical flag
        int typeoctet = in.read() & 0xff;
        type = typeoctet & 0x7f;
        critical = (typeoctet & 0x80) > 0 ? true : false;  
    }
}
