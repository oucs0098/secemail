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

package core.algorithmhandlers.openpgp;
import core.algorithmhandlers.openpgp.packets.*;
import core.exceptions.AlgorithmException;
import java.io.*;

/**
 * <p>A class that writes PGP packets to a byte stream.</p>
 */
public class OpenPGPPacketOutputStream {

    /** Stream to write packet bytes to.*/
    private OutputStream outputStream;

    /** Creates a new instance of OutgoingPGPPacketStream
     * @param stream The stream to write package data to.
     */
    public OpenPGPPacketOutputStream(OutputStream stream) {
        outputStream = stream;
    }

    /** <p>Write a given packet to the stream and then flushes it.</p>
     * @throws IOException if there was a problem writing to the stream.
     * @throws AlgorithmException if there was a problem encoding the packet data.
     */
    public void writePacket(Packet packet) throws IOException, AlgorithmException {
        outputStream.write(packet.encodePacket());
        outputStream.flush();
    }
    
    /** <p>Close the stream.</p>
     * <p>Flushes and closes the stream. Once closed, a stream can not be reopened.</p>
     */
    public void close() throws IOException {
        outputStream.flush();
        outputStream.close();
    }
}
