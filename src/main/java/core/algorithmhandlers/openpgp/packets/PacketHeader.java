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
import java.io.*;

/**
 * <p>OpenPGP Packet header.</p>
 * <p>This class represents an openPGP packet header.</p>
 */
public class PacketHeader {
    
    /** Packet type. */
    private int type;
    
    /** Is this a new format header or not. */
    private boolean newformat;
    
    /** The length of the header (if old format). */
    private int lengthtype;
    
    /** The body length. */
    private long bodylength;
    
    /** Creates a packet header (in an input stream). 
     * @param packettype The type of packet.
     * @param packetnewformat Is the packet new or old format.
     * @param packetlengthtype The length type of an oldstyle header, use -1 if new format header.
     * @param packetbodylength The length of the body. A body length of -1 denotes a oldstyle intermediate packet.
     * @throws AlgorithmException if there was a problem creating the packet header.
     */
    public PacketHeader(int packettype, boolean packetnewformat, int packetlengthtype, long packetbodylength) throws AlgorithmException {
        
        if (packettype <= 0) throw new AlgorithmException("Invalid packet type.");
        
        setType(packettype);
        setNewFormat(packetnewformat);
        
        if (isNewFormat())
            setLengthType(-1);
        else
            setLengthType(packetlengthtype);
        
        setBodyLength(packetbodylength);
    }
    
    /** Create a packet header and calculate length type for you.
     * @param packettype The type of packet.
     * @param packetnewformat Is the packet new format or not.
     * @param packetbodylength The size in bytes of the amount of data you wish to write in the packet. A body length of -1 denotes a oldstyle intermediate packet.
     * @throws AlgorithmException if there was a problem creating the packet header.
     */
    public PacketHeader(int packettype, boolean packetnewformat, long packetbodylength) throws AlgorithmException {
        
        this(packettype, packetnewformat, 0, packetbodylength);
        
        int lengthtype = 0;
        
        if ((!packetnewformat) && (packetbodylength==-1)) {
            lengthtype = 3; // old style intermediate
        } else {
            if (packetbodylength < 256) {
                lengthtype = 0;
            } else if (packetbodylength < 65536) {
                lengthtype = 1;
            } else if (packetbodylength < 4294967296L) {
                lengthtype = 2;
            } else {
                throw new AlgorithmException("Maximum packet length exceeded");
            }
        }
        
        setLengthType(lengthtype);
    }
    
    /**
     * <p>A constructor for use by packets that do not yet know the encoded packet size information. </p>
     * <p>This information <b>MUST</b> be provided later in the packet's encodePacket() method.</p>
     * @param packettype The type of packet.
     * @param packetnewformat Is the packet new format or not.
     * @throws AlgorithmException if there was a problem creating the packet header.
     */
    public PacketHeader(int packettype, boolean packetnewformat) throws AlgorithmException {
        this(packettype, packetnewformat, 0, 0);
    }
        
    /** Get the type of packet.*/
    public int getType() {
        return type;
    }
    
    /** Set the type of packet. */
    protected void setType(int packettype) {
        type = packettype;
    }
    
    /** Is this a new format packet? */
    public boolean isNewFormat() {
        return newformat;
    }
    
    /** Set the format of this packet, new or old. */
    protected void setNewFormat(boolean format) {
        newformat = format;
    }
    
    /** Get the header length. */
    public int getLengthType() {
        return lengthtype;
    }
    
    /** Set the header length. */
    protected void setLengthType(int lengtht) {
        lengthtype = lengtht;
    }
    
    /** Get the length of the body. */
    public long getBodyLength() {
        return bodylength;
    }
    
    /** Set the length of the body. */
    protected void setBodyLength(long length) {
        bodylength = length;
    }

    
    /** Encode the header into a binary representation. 
     * @throws AlgorithmException if there was a problem encoding the packet header.
     */
    public byte[] encodeHeader() throws AlgorithmException{
        
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        if (isNewFormat()) {
            out.write((192 + getType()) & 0xFF); // new format packet tag

            // new format size
            if (getBodyLength()<192) {
                out.write((byte)getBodyLength());
            } else if (getBodyLength()<8384) {
                out.write((byte)(192 + (byte)((getBodyLength()-192)>>8)));
                out.write((byte)(getBodyLength()-192));
            } else if (getBodyLength()<4294967296L) {
                out.write(255 & 0xFF);
                out.write((byte)(getBodyLength() >> 24));
                out.write((byte)(getBodyLength() >> 16));
                out.write((byte)(getBodyLength() >>  8));
                out.write((byte)(getBodyLength()));
            }
        } else {
            out.write((byte)(128 + ( getType() << 2) + getLengthType()) & 0xFF); // old format packet tag

            // old format size
            if (getLengthType() == 0) {
                out.write((byte)getBodyLength());
            } else if (getLengthType() == 1) {
                out.write((byte)(getBodyLength() >> 8));
                out.write((byte)getBodyLength() );
            } else {
                out.write((byte)(getBodyLength() >> 24));
                out.write((byte)(getBodyLength() >> 16));
                out.write((byte)(getBodyLength() >>  8));
                out.write((byte)(getBodyLength()));
            }
        }

        return out.toByteArray();

    }
}
