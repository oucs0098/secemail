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
import core.exceptions.AlgorithmException;
import java.io.*;

/**
 * <p>Authorise a specified key to issue revocation signatures for this key.</p>
 */
public class RevocationKeySubPacket extends FlagsSubPacket {
    
    /** Class flag. Must be set*/
    public static final int CLASS = 0x80;
    /** Is this packet sensitive. Packet should not be exported if set. */
    public static final int SENSITIVE = 0x40;
    
    
    /** Algorithm ID */
    private int algorithm;
    
    /** Fingerprint ID */
    private byte fingerprint[];
    
    /** Creates a new instance of RevocationKeySubPacket */
    public RevocationKeySubPacket() {
        super(1);
        setFlag(0, CLASS, true);
    }
    
    /** Creates a new instance of RevocationKeySubPacket.
     * @param flags a bunch of flags... 0x80 will always be set.
     * @param algorithmID The algorithm for PK key algorithm.
     * @param print[] 20 bytes of key fingerprint.
     * @throws AlgorithmException if something went wrong.
     */
    public RevocationKeySubPacket(int flags, int algorithmID, byte print[]) throws AlgorithmException {
        super(1);
        setFlag(0, CLASS, true);
        
        setAlgorithm(algorithmID);
        
        if (print.length!=20) 
            throw new AlgorithmException("Fingerprint is not 20 bytes long");
        setFingerprint(print);
        
        setSubPacketHeader(new SignatureSubPacketHeader(12, false, 22));
    }
    
    /** Set the SENSITIVE flag.
     * @param set Toggle the flag on (true) or off (false).
     */
    public void setSensitiveFlag(boolean set) {
        setFlag(0, SENSITIVE, set);
    }
    
    /** Returns true if the SENSITIVE flag has been set. */
    public boolean getSensitiveFlag() {
        return getFlag(0, SENSITIVE);
    }
    
    /** Set fingerprint algorithm ID */
    public void setAlgorithm(int algID) {
        algorithm = algID;
    }
    
    /** Get the fingerprint algorithm ID */
    public int getAlgorithm() {
        return algorithm;
    }
    
    /** Set the 20 byte fingerprint */
    public void setFingerprint(byte print[]) {
        fingerprint = print;
    }
    
    /** Get the fingerprint */
    public byte[] getFingerprint() {
        return fingerprint;
    }
    
    /**
     * <p>Construct a packet from a preloaded data array.</p>
     * <p>This method allows the V4SignatureMaterial class to read a full packet in before processing, allowing
     * the read method to better handle unknown packets.</p>
     * @param data[] The full packet.
     * @throws IOException if something went wrong.
     */
    public void decode(byte[] data) throws IOException {
        
        if (data.length != 22) throw new IOException("Revocation key signature packet has the wrong length (length = "+data.length+" bytes, should be 22).");
        
        super.decode(data);
        
        setAlgorithm((int)data[1]);
        
        byte tmp[] = new byte[20];
        System.arraycopy(data, 2, tmp, 0, 20);
        setFingerprint(tmp);
    }    
    
    /**
     * <p>Write the packet (with header) out to a byte stream.</p>
     * @throws IOException if something went wrong.
     */
    public void encode(OutputStream out) throws IOException {
        super.encode(out);
        
        out.write(getAlgorithm() & 0xff);
        out.write(getFingerprint());
    }
}
