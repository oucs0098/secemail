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
 * <p>A trust packet is used inside keyrings to store implementation specific trust matrix information.</p>
 * <p>It should not be exported.</p>
 */
public class TrustPacket extends Packet {
    
    /** Raw trust information. */
    private byte trustmatrix[];

    /** Creates a new instance of TrustPacket with no header */
    public TrustPacket() {
    }
    
    /** A more useful constructor. Automatically creates header. 
     * @throws AlgorithmException if the packet could not be created.
     */
    public TrustPacket(byte trust[]) throws AlgorithmException {
        setTrust(trust);
        setPacketHeader(new PacketHeader(12, false, (long)trust.length));
    }
    
    /** Set the trust matrix information. */
    protected void setTrust(byte trust[]) {
        trustmatrix = trust;
    }
    
    /** Get the trust matrix information. */
    public byte[] getTrust() {
        return trustmatrix;
    }
    
    /**
     * <p>A method constructs a packet out of raw binary data.</p>
     * <p>You should implement this in all your packets. If a packet is a container packet
     * you must also populate the subpackets vector by extracting and constructing the relevent packets.</p>
     * @throws AlgorithmException if there was a problem.
     */
    public void buildPacket(byte[] data) throws AlgorithmException {
        setTrust(data);
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

            out.write(getPacketHeader().encodeHeader());
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

            out.write(getTrust());

            return out.toByteArray();
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
}
