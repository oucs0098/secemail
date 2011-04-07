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
import java.util.zip.*;

/**
 * <p>A class representing a compressed data packet.</p>
 * <p>A compressed data packet is a container object that can contain other PGP packets. </p>
 */
public class CompressedDataPacket extends ContainerPacket {
    
    /** ZIP (RFC 1951) compression */
    public static final byte ZIP = 1;
    
    /** ZLIB (RFC 1950) compression */
    public static final byte ZLIB = 2;
    
    /** BZip2 (BZ2) compression */
    public static final byte BZ2 = 3;
    
    /** What algorithm should the packet use to compress the data. */
    private byte algorithm;
    
    /** Creates a new instance of CompressedDataPacket with no header */
    public CompressedDataPacket() {
    }
    
    /** 
     * <p>Create a CompressedDataPacket to use a given algorithm to compress the data.</p>
     * <p>This constructor creates the appropriate header. You should add packets to this packet seperately.</p>
     * <p><b>IMPORTANT NOTE:</b> Unless this packet is loaded from a stream _and_ no calls to add() have been made, the PacketHeader's length type and bodylength tags
     * are MEANINGLESS! It is not possible to accurately calculate the size of the body before it is encoded. Therefore this class'
     * encodePacket() method recalculates the header length information.
     * @throws AlgorithmException if there was a problem.
     */
    public CompressedDataPacket(byte compressionalgorithm) throws AlgorithmException {
        setCompressionAlgorithm(compressionalgorithm);
        setPacketHeader(new PacketHeader(8,false)); 
    }
    
    /** Set the compression algorithm to use. */
    protected void setCompressionAlgorithm(byte compressionalgorithm) {
        algorithm = compressionalgorithm;
    }
    
    /** Get the compression algorithm that will be used when this packet is encoded. */
    public byte getCompressionAlgorithm() {
        return algorithm;
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

            // Read algorithm code
            setCompressionAlgorithm((byte)(in.read() & 0xFF));

            // process compressed data
            ByteArrayOutputStream uncompressed = new ByteArrayOutputStream();

            switch (getCompressionAlgorithm()) {
                case 0 : { // No compression. A little pointless, but here anyway.
                    byte b[] = new byte[in.available()];
                    in.read(b);
                    uncompressed.write(b);
                } break; // no compression
                case ZIP : { // ZIP (RFC 1951)
                    InflaterInputStream decompressor = new InflaterInputStream(in, new Inflater(true));

                    int b;
                    while ((b = decompressor.read())!=-1) 
                        uncompressed.write(b);
                    
                    decompressor.close();
                   
                } break; 
                case ZLIB : { // ZLIB (RFC 1950)
                	InflaterInputStream decompressor = new InflaterInputStream(in);

                    int b;
                    while ((b = decompressor.read())!=-1) 
                        uncompressed.write(b);
                    
                    decompressor.close();
                } break;
                
                default : throw new AlgorithmException("Unsupported compression algorithm requested.");
            }

            // process uncompressed data into packets
            buildMultiplePackets(uncompressed.toByteArray());
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
    /**
     * <p>A method that produces a straight binary representation of this packet.</p>
     * <p>You should override this as necessary.</p>
     * <p>You should also encode the header as part of this method by calling the header object's
     * encodeHeader method.</p>
     * <p><b>IMPORTANT NOTE:</b> Since there isn't a reliable way to 100% accurately predict the size of the message body before it is compressed,
     * therefor this method recalculates the packet header. All previous body length and length type information is clobbered. </p>
     * @throws AlgorithmException if there was a problem.
     */
    public byte[] encodePacket() throws AlgorithmException {
        
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte body[] = encodePacketBody();

            // recreate header
            setPacketHeader(new PacketHeader(8, false, body.length));

            // encode header
            out.write(getPacketHeader().encodeHeader());
            
            // write body
            out.write(body);
            
            // return encoded packet
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
            byte compressed[];

            // encode and compress the packets contained within this 
            switch (getCompressionAlgorithm()) {
                case 0 : compressed = encodeMultiplePackets(); break; // no compression
                case ZIP : { // ZIP (RFC 1951)
                    ByteArrayOutputStream rawdata = new ByteArrayOutputStream();

                    DeflaterOutputStream compressor = new DeflaterOutputStream(rawdata, new Deflater(Deflater.DEFAULT_COMPRESSION, true));
                    compressor.write(encodeMultiplePackets());

                    compressor.finish();
                    
                    compressed = rawdata.toByteArray();
                } break;
                case ZLIB : { // ZLIB (RFC 1950)
                    ByteArrayOutputStream rawdata = new ByteArrayOutputStream();

                    DeflaterOutputStream compressor = new DeflaterOutputStream(rawdata);
                    compressor.write(encodeMultiplePackets());

                    compressor.finish();
                    
                    compressed = rawdata.toByteArray();
                } break;
                //TODO: Add BZ2
                
                default : throw new AlgorithmException("Unsupported compression algorithm requested.");
            }

            // write algorithm
            out.write((int)getCompressionAlgorithm());
            
            // write compressed packet data
            out.write(compressed);
            
            // return encoded packet
            return out.toByteArray();
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
}
