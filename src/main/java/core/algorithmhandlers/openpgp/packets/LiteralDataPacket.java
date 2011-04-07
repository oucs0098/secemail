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
import java.util.*;
import java.io.*;

/**
 * <p>A packet representing literal binary or text data. It is up to you to process this as you see fit, including
 * processing crlf pairs into native encoding.</p>
 */
public class LiteralDataPacket extends Packet {
    
    /** Format of the message, either 'b' or 't' for binary and text formatting respectively, or 'l' for local (depreciated). */
    private byte format;
    
    /** File name. Must be no greater than 255 bytes long.*/
    private String filename;
    
    /** Modification date, creation time, or 0 for current */
    private long moddate;
    
    /** Literal data */
    private byte data[];
    
    /** Creates a new instance of LiteralDataPacket with no header */
    public LiteralDataPacket() {
    }
    
    /** Create a new instance of the packet.
     * Date is automatically set to "now" using Date.getTime(). This value is divided by 1000 so it fits 
     * in an unsigned integer. Multiply by 1000 to get the approximate original value back... call setModDate to change this. 
     * @param frmat The format of the packet 'b' for binary, 't' for text, or 'l' for local (depreciated).
     * @param file The filename of the literal data. If this is "_CONSOLE" then the packet will be marked as sensitive.
     * @param rawdata A byte array containing the packet data.
     * @throws AlgorithmException if the packet could not be created.
     */
    public LiteralDataPacket(byte frmat, String file, byte rawdata[]) throws AlgorithmException {
        setFormat(frmat);
        setFilename(file);
        setModDate(new Date().getTime() / 1000); 
        setData(rawdata);
        
        long size = 1+1+file.length()+4+rawdata.length;
        setPacketHeader(new PacketHeader(11, false, size));

    }
    
    /** <p>Set the format of the packet data.</p>
     * @param type Use either 'b' for binary, or 't' for text, or 'l' for binary local. If type is neither, binary is assumed.
     */
    protected void setFormat(byte type) {
        if ((type == 'b') || (type == 't') || (type == 'u') || (type == 'l'))
            format = type;
        else 
            format = 'b';
    }
    
    /** Get the packet's format information. */
    public byte getFormat() {
        return format;
    }
    
    /** <p>Set the literal packet filename.</p>
     * @param name The name of the literal packet data. This must be no longer than 255 characters. If the filename is "_CONSOLE" then eyesonly is automatically set to TRUE.
     */
    protected void setFilename(String name) {
        
        filename = name;
    }
    
    /** Get the filename of the literal data packet. */
    public String getFilename() {
        return filename;
    }
    
    /** The modification date of this packet.
     * @param The date this packet was last modified / created, or 0 for the present date.
     */
    protected void setModDate(long date) {
        moddate = date;
    }
    
    /** Get the modification date. */
    public long getModDate() {
        return moddate;
    }
    
    /** Set the literal data contained in the packet. */
    protected void setData(byte packetdata[]) {
        data = packetdata;
    }
    
    /** Return the data. */
    public byte[] getData() {
        return data;
    }
    
    /**
     * <p>A method constructs a packet out of raw binary data.</p>
     * <p>You should implement this in all your packets. If a packet is a container packet
     * you must also populate the subpackets vector by extracting and constructing the relevent packets.</p>
     * @throws AlgorithmException if there was a problem.
     */
    public void buildPacket(byte[] data) throws AlgorithmException {
        try {
            ByteArrayInputStream in = new ByteArrayInputStream(data);
        
            // read format
            setFormat((byte)(in.read() & 0xFF));

            // read filename size
            int filenamesize = in.read();

            // read filename
            if (filenamesize>0) {
                byte filenm[] = new byte[filenamesize];
                in.read(filenm);
                setFilename(new String(filenm));
            }

            // load date
            long date = ( ((in.read() & 0xFFl) << 24) 
                        | ((in.read() & 0xFFl) << 16)
                        | ((in.read() & 0xFFl) <<  8)
                        | ((in.read() & 0xFFl) ));
            setModDate(date);

            // rest of the data
            byte dat[] = new byte[in.available()];
            
            in.read(dat);
            setData(dat);
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }

    }
    
    /**
     * <p>A method that produces a straight binary representation of this packet.</p>
     * <p>You should override this as necessary.</p>
     * <p>You should also encode the header as part of this method by calling the header object's
     * encodeHeader method.</p>
     * @throws AlgorithmException if there was a problem.
     */
    public byte[] encodePacket() throws AlgorithmException {
        
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            // write header
            out.write(getPacketHeader().encodeHeader());

            // write body
            out.write(encodePacketBody());
            
            return out.toByteArray();
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
    /**
     * <p>A method that produces a straight binary representation of this packet's BODY.</p>
     * <p>You should override this as necessary.</p>
     * @throws AlgorithmException if there was a problem.
     */
    public byte[] encodePacketBody() throws AlgorithmException {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            // write format
            out.write(getFormat() & 0xFF);

            // write filename and length
            out.write(getFilename().length() & 0xFF);
            out.write(getFilename().getBytes());         

            // write date
            out.write((int)((getModDate() >> 24) & 0xFF));
            out.write((int)((getModDate() >> 16) & 0xFF));
            out.write((int)((getModDate() >> 8) & 0xFF));
            out.write((int)((getModDate() >> 0) & 0xFF));

            // write data
            out.write(getData());
            
            return out.toByteArray();
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
}
