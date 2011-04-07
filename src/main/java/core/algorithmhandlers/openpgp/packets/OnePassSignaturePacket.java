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
 * <p>A class representing a one pass signature packet. This is not compatible with PGP 2.6.x or earlier.</p>
 */
public class OnePassSignaturePacket extends Packet {
    
    /** Packet version. Currently version 3. */
    private int version;
    
    /** Signature type. */
    private int type;
    
    /** hash algorithm used. */
    private int hashAlgorithm;
    
    /** public key algorithm used. */
    private int publicKeyAlgorithm;
    
    /** Key id of the signing key. */
    private byte keyID[];
    
    /** Nested or not. */
    private boolean nested;
    
    /** Creates a new instance of OnePassSignaturePacket with no header */
    public OnePassSignaturePacket() {
    }
    
    /**A more useful constructor. Automatically creates header. 
     * @param sigtype Signature type.
     * @param hash The hash algorithm used.
     * @param publickey The public key algorithm used.
     * @param kID An 8 bit byte array representing the key id of the key used for signing.
     * @param nest Is the packet nested or not.
     * @throws AlgorithmException if the packet could not be created.
     */
    public OnePassSignaturePacket(int sigtype, int hash, int publickey, byte kID[], boolean nest) throws AlgorithmException {
        setVersion(3);
        setType(sigtype);
        setHashAlgorithm(hash);
        setPublicKeyAlgorithm(publickey);
        setKeyID(kID);
        setNested(nest);
        setPacketHeader(new PacketHeader(4, false, 13));
    }
    
    /** Set the version of the packet. Should be v3. */
    protected void setVersion(int ver) {
        version = ver;
    }
    
    /** Get the version of the packet. */
    public int getVersion() {
        return version;
    }
    
    /** Set the signature type. */
    protected void setType(int sigtype) {
        type = sigtype;
    }
    
    /** Get the signature type. */
    public int getType() {
        return type;
    }
    
    /** Set the hash algorithm to use. */
    protected void setHashAlgorithm(int algorithm) {
        hashAlgorithm = algorithm;
    }
    
    /** Get the hash algorithm used. */
    public int getHashAlgorithm() {
        return hashAlgorithm;
    }
    
    /** Set the public key algorithm to use. */
    protected void setPublicKeyAlgorithm(int algorithm) {
        publicKeyAlgorithm = algorithm;
    }
    
    /** Get the public key algorithm being used. */
    public int getPublicKeyAlgorithm() {
        return publicKeyAlgorithm;
    }
    
    /** Set the key id of the key used to sign the message. */
    protected void setKeyID(byte id[]) {
        keyID = id;
    }
    
    /** Get the key id of the key used to sign the message. */
    public byte[] getKeyID() {
        return keyID;
    }
    
    /** Set nested on and off. See spec for meaning. */
    protected void setNested(boolean nest) {
        nested = nest;
    }
    
    /** Get the status of the nested flag. */
    public boolean getNested() {
        return nested;
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
        
            setVersion(in.read() & 0xFF);
            if (getVersion()!=3) throw new AlgorithmException("Only version 3 One Pass Signature Packets are supported.");
            
            setType(in.read() & 0xFF);
            setHashAlgorithm(in.read() & 0xFF);
            setPublicKeyAlgorithm(in.read() & 0xFF);
            
            byte id[] = new byte[8];
            in.read(id);
            setKeyID(id);
            
            if ((in.read() & 0xFF) == 0)
                setNested(true);
            else
                setNested(false);
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

            out.write(getVersion() & 0xFF);
            out.write(getType() & 0xFF);
            out.write(getHashAlgorithm() & 0xFF);
            out.write(getPublicKeyAlgorithm() & 0xFF);
            
            out.write(getKeyID());
            
            if (getNested()) 
                out.write(0);
            else
                out.write(1);

            return out.toByteArray();
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
}
