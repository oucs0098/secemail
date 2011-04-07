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
import core.algorithmhandlers.openpgp.packets.PacketHeader;
import core.exceptions.AlgorithmException;
import java.io.IOException;

/**
 * <p>A PGP Packet.</p>
 * <p>The abstract root class for all PGP packets. Extend and override this class to handle specific packets.</p>
 */
public abstract class Packet {
    
    /** The header of this packet. */
    private PacketHeader header;
    
    /** Generic constructor.*/
    public Packet() {
    }

    /** Set the packet header. */
    public void setPacketHeader(PacketHeader packetHeader) {
        header = packetHeader;
    }
    
    /** Get the packet header. */
    public PacketHeader getPacketHeader() {
        return header;
    }
    
    /**
     * <p>A method constructs a packet out of raw binary data.</p>
     * <p>You should implement this in all your packets. If a packet is a container packet
     * you must also populate the subpackets vector by extracting and constructing the relevent packets.</p>
     * @param data[] The packet body data as a raw binary bytestream. If you are using OpenPGPPacketInputStream the header will automatically be created for you. 
     * @throws AlgorithmException if there was a problem.
     */
    public abstract void buildPacket(byte data[]) throws AlgorithmException;
    
    /** 
     * <p>A method that produces a straight binary representation of this packet.</p>
     * <p>You should override this as necessary.</p>
     * <p>You should also encode the header as part of this method by calling the header object's
     * encodeHeader method.</p>
     * @throws AlgorithmException if there was a problem.
     */
    public abstract byte[] encodePacket() throws AlgorithmException;
    
    /** 
     * <p>A method that produces a straight binary representation of this packet's BODY.</p>
     * <p>You should override this as necessary.</p>
     * @throws AlgorithmException if there was a problem.
     */
    public abstract byte[] encodePacketBody() throws AlgorithmException;
}
