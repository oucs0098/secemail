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
import core.algorithmhandlers.openpgp.OpenPGPPacketInputStream;
import java.util.Vector;
import java.io.*;

/**
 * <p>An abstract class representing PGP packets that can contain other packets.</p>
 * <p>The class adds an interface for accessing subpackets.</p>
 * <p>All packets that contain other packets (such as a Compressed Data Packet) should extend this class.</p>
 */
public abstract class ContainerPacket extends Packet {

    /** A vector list of sub packets contained by this packet.
     * This should be populated by a packets buildPacket method.
     */
    private Vector subpackets;
    
    /** Create a default instance of this object and initialise storage. */
    public ContainerPacket() {
        subpackets = new Vector();
    }
    
    /** Add a packet to the container. */
    public void add(Packet p) {
        subpackets.addElement(p);
    }
    
    /** <p> Unpack all a given subpacket.</p>
     * <p>This is not recursive. If a sub packet contains packets, you should call its unpack method
     * as appropriate.</p>
     */
    public Packet unpack(int item) {
        return (Packet)subpackets.elementAt(item);
    }
    
    /** Return the number of packets currently stored in the container. */
    public int getNumberPacked() {
        return subpackets.size();
    }
        
    /**
     * <p>Adds packets to the container from a byte array containing one or more raw encoded packets.</p>
     * @throws AlgorithmException if something went wrong.
     */
    public void buildMultiplePackets(byte data[]) throws AlgorithmException {

        try {
            OpenPGPPacketInputStream packin = new OpenPGPPacketInputStream(new ByteArrayInputStream(data));

            Packet p = null;

            do {

                p = packin.readPacket();

                if (p!=null) {
                    add(p);
                }

            } while (p!=null);

            packin.close();
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
    /**
     * <p>A method that calls the encodePacket method on all contained packets and returns the result.</p>
     * @throws AlgorithmException if there was a problem.
     */
    public byte[] encodeMultiplePackets() throws AlgorithmException {
       
        try {
            
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            for (int n = 0; n < getNumberPacked(); n++) {
                out.write(unpack(n).encodePacket());
            }
            return out.toByteArray();
        
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
}
