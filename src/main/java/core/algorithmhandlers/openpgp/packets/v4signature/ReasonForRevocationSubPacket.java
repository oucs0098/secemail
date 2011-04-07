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
import java.lang.String;
import core.exceptions.AlgorithmException;

/**
 * <p>A packet defining the reason for a revocation, both in computer and human readable form.</p>
 */
public class ReasonForRevocationSubPacket extends SignatureSubPacket {
    
    public static final int NO_REASON = 0x00;
    
    public static final int KEY_SUPERSEDED = 0x01;
    
    public static final int KEY_MATERIAL_COMPROMISED = 0x02;
    
    public static final int KEY_NO_LONGER_USED = 0x03;
    
    public static final int USER_ID_INFORMATION_INVALID = 0x20;
 
    
    /** Reason code */
    private int reasonCode;
    
    /** Reason text */
    private String reasonText;
    
    /** Creates a new instance of ReasonForRevocationSubPacket */
    public ReasonForRevocationSubPacket() {
    }
    
    /** Creates a new instance of ReasonForRevocationSubPacket */
    public ReasonForRevocationSubPacket(int code) throws AlgorithmException {
        reasonCode = code;
        
        switch (code) {
            case NO_REASON : reasonText = "No reason specified"; break;
            case KEY_SUPERSEDED : reasonText = "Key is superseded"; break;
            case KEY_MATERIAL_COMPROMISED : reasonText = "Key has been compromised"; break;
            case KEY_NO_LONGER_USED : reasonText = "Key is no longer used"; break;
            case USER_ID_INFORMATION_INVALID : reasonText = "User ID is no longer valid"; break;
            default : throw new AlgorithmException("Invalid revocation reason given!");
        }
        
        setSubPacketHeader(new SignatureSubPacketHeader(29, false, 1+reasonText.length()));
    }
    
    /** Return the reason code. */
    public int getReasonCode() {
        return reasonCode;
    }
    
    /** Return the reason text. */
    public String getReasonText() {
        return reasonText;
    }
    
    /**
     * <p>Construct a packet from a preloaded data array.</p>
     * <p>This method allows the V4SignatureMaterial class to read a full packet in before processing, allowing
     * the read method to better handle unknown packets.</p>
     * @param data[] The full packet.
     * @throws IOException if something went wrong.
     */
    public void decode(byte[] data) throws IOException {
        byte tmp[] = new byte[data.length-1];
        System.arraycopy(data, 1, tmp, 0, tmp.length);
        
        reasonCode = (int)(data[0] & 0xff);
        reasonText = new String(tmp, "UTF-8");
    }
    
    /**
     * <p>Write the packet (with header) out to a byte stream.</p>
     * @throws IOException if something went wrong.
     */
    public void encode(OutputStream out) throws IOException {
        getSubPacketHeader().encode(out);
        out.write(getReasonCode());
        out.write(getReasonText().getBytes("UTF-8"));
    }
    
}
