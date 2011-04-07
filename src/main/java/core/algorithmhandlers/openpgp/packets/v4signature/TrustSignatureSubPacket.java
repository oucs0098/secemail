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
 * <p>A sub packet defining the amount of trust in the owner of the key the signer has.</p>
 */
public class TrustSignatureSubPacket extends SignatureSubPacket {

    /* Depth values */
    public static final int NORMAL_SIGNATURE = 0;
    public static final int TRUSTED_INTRODUCER = 1;
    public static final int META_INTRODUCER = 2;
    
    /* Amount values */
    public static final int NO_TRUST = 0;
    public static final int PARTIAL_TRUST = 60;
    public static final int TOTAL_TRUST = 120;

    
    /** Trust depth */
    private int depth = NORMAL_SIGNATURE;
    /** Trust amount */
    private int amount = NO_TRUST;
    
    /** Creates a new instance of TrustSubPacket */
    public TrustSignatureSubPacket() {
    }
    
    /** Creates a new instance of TrustSubPacket */
    public TrustSignatureSubPacket(int depth, int amount) {
        setDepth(depth);
        setAmount(amount);
        setSubPacketHeader(new SignatureSubPacketHeader(5, false, 2));
    }
    
    /** <p>Set the trust depth. </p>
     * <p>NORMAL_SIGNATURE = 0, TRUSTED_INTRODUCER = 1, META_INTRODUCER = 2.</p>
     */
    public void setDepth(int trustdepth) {
        depth = trustdepth;
    }
    
    /** Get the trust depth.*/
    public int getDepth() {
        return depth;
    }
    
    /** <p>Set the trust amount. </p>
     * <p>NO_TRUST = 0, PARTIAL_TRUST = 60, TOTAL_TRUST = 120.</p>
     */
    public void setAmount(int trustamount) {
        amount = trustamount;
    }
    
    /** Get the trust amount.*/
    public int getAmount() {
        return amount;
    }
    
    /**
     * <p>Construct a packet from a preloaded data array.</p>
     * <p>This method allows the V4SignatureMaterial class to read a full packet in before processing, allowing
     * the read method to better handle unknown packets.</p>
     * @param data[] The full packet.
     * @throws IOException if something went wrong.
     */
    public void decode(byte[] data) throws IOException {
        setDepth((int)data[0]);
        setAmount((int)data[1]);
    }
    
    /**
     * <p>Write the packet (with header) out to a byte stream.</p>
     * @throws IOException if something went wrong.
     */
    public void encode(OutputStream out) throws IOException {
        getSubPacketHeader().encode(out);
        out.write(getDepth());
        out.write(getAmount());
    }
    
}
