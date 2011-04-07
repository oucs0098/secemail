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
import java.security.*;

/**
 * <p>This class implements OpenPGP signature packets.</p>
 */
public class SignaturePacket extends Packet {
    
    /**
     <p>Signature of a binary document.</p>
     <p>Typically, this means the signer owns it, created it, or
     certifies that it has not been modified.</p>
     */
    public static final int BINARY_DOC = 0x00;
    
    /**
     <p>Signature of a canonical text document.</p>
     <p>Typically, this means the signer owns it, created it, or
     certifies that it has not been modified.  The signature is
     calculated over the text data with its line endings converted
     to <CR><LF> and trailing blanks removed.</p>
     */
    public static final int CTEXT_DOC = 0x01;
    
    /**
     <p>Standalone signature.</p>
     <p>This signature is a signature of only its own subpacket
     contents. It is calculated identically to a signature over a
     zero-length binary document. Note that it doesn't make sense to
     have a V3 standalone signature.</p>
     */
    public static final int STANDALONE = 0x02;
    
    /**
     <p>Generic certification of a User ID and Public Key packet.</p>
     <p>The issuer of this certification does not make any particular
     assertion as to how well the certifier has checked that the
     owner of the key is in fact the person described by the user
     ID.  Note that all PGP "key signatures" are this type of
     certification.</p>
     */
    public static final int GENERIC_UID = 0x10;
    
    /**
     <p>Persona certification of a User ID and Public Key packet.</p>
     <p>The issuer of this certification has not done any verification
     of the claim that the owner of this key is the user ID
     specified.</p>
     */
    public static final int PERSONA_UID = 0x11;
    
    /**
     <p>Casual certification of a User ID and Public Key packet.</p>
     <p>The issuer of this certification has done some casual
     verification of the claim of identity.</p>
     */
    public static final int CASUAL_UID = 0x12;
    
    /**
     <p>Positive certification of a User ID and Public Key packet.</p>
     <p>The issuer of this certification has done substantial
     verification of the claim of identity.</p>

     <p>Please note that the vagueness of these certification claims is
     not a flaw, but a feature of the system. Because PGP places
     final authority for validity upon the receiver of a
     certification, it may be that one authority's casual
     certification might be more rigorous than some other
     authority's positive certification. These classifications allow
     a certification authority to issue fine-grained claims.</p>
     */
    public static final int POSITIVE_UID = 0x13;
    
    /**
     <p>Subkey Binding Signature.</p>
     <p>This signature is a statement by the top-level signing key
     indicates that it owns the subkey. This signature is calculated
     directly on the subkey itself, not on any User ID or other
     packets.</p>
     */
    public static final int SUBKEY_BIND = 0x18;
    
    /**
     <p>Primary key Binding Signature.</p>
     <p>This signature is a statement by a signing subkey, indicating that
     it is owned by the primary key and subkey. This signature is calculated
     the same way as a 0x18 signature: directly on the primary key and
     subkey, and not on any User ID or other packets.</p>
     */
    public static final int PRIMARYKEY_BIND = 0x19;
    
    /**
     <p>Signature directly on a key.</p>
     <p>This signature is calculated directly on a key.  It binds the
     information in the signature subpackets to the key, and is
     appropriate to be used for subpackets that provide information
     about the key, such as the revocation key subpacket. It is also
     appropriate for statements that non-self certifiers want to
     make about the key itself, rather than the binding between a
     key and a name.</p>
     */
    public static final int DIRECT_KEY = 0x1F;
    
    /**
     <p>Key revocation signature.</p>
     <p>The signature is calculated directly on the key being revoked.
     A revoked key is not to be used.  Only revocation signatures by
     the key being revoked, or by an authorized revocation key,
     should be considered valid revocation signatures.</p>
     */
    public static final int KEY_REVOCATION = 0x20;
    
    /**
     <p>Subkey revocation signature.</p>
     <p>The signature is calculated directly on the subkey being
     revoked.  A revoked subkey is not to be used.  Only revocation
     signatures by the top-level signature key that is bound to this
     subkey, or by an authorized revocation key, should be
     considered valid revocation signatures.</p>
     */
    public static final int SUBKEY_REVOCATION = 0x28;
    
    /**
     <p>Certification revocation signature.</p>
     <p>This signature revokes an earlier user ID certification
     signature (signature class 0x10 through 0x13). It should be
     issued by the same key that issued the revoked signature or an
     authorized revocation key The signature should have a later
     creation date than the signature it revokes.</p>
     */
    public static final int CERT_REVOCATION = 0x30;
    
    /**
     <p>Timestamp signature.</p>
     <p>This signature is only meaningful for the timestamp contained
     in it.</p>
     */
    public static final int TIMESTAMP = 0x40;
    
    /**
     <p>Third-party Confirmation signature.</p>
     <p>This signature is a signature over some other OpenPGP signature
     packet(s). It is analogous to a notary seal on the signed data.
     A third-party signature should include Signature Target subpacket(s)
     to give easy identification. Note that we really do mean SHOULD. There
     are plausible uses for this (such as a blind party that only sees the 
     signature, not the key nor source document) that cannot include a target
     subpacket.</p>
     */
    public static final int THIRDPARTY_CONFIRM = 0x50;

    /** Version octet */
    private int version;
    
    /** The signature material */
    private SignatureMaterial data;
    
    /** Creates a new instance of SignaturePacket without header*/
    public SignaturePacket() {
    }
    
    /** Creates a new instance of SignaturePacket*/
    public SignaturePacket(SignatureMaterial data) throws AlgorithmException {
        if (data instanceof V3SignatureMaterial)
            setVersion(3);
        else if (data instanceof V4SignatureMaterial) 
            setVersion(4);
        else 
            throw new AlgorithmException("Unrecognised signature material type");
        
        setSignatureData(data);
        
        setPacketHeader(new PacketHeader(2, false, data.encode().length+1));
    }
    
    /** Return the version type of the packet, either 3 or 4. */
    public int getVersion() {
        return version;
    }
    
    /** Set the version type of the packet, 3 or 4. */
    protected void setVersion(int ver) {
        version = ver;
    }
    
    /** <p>Query the signature material packet for key ID information.</p>
     * <p>This interface will obtain key id information from the stored key material packet.</p>
     * @throws AlgorithmException if no signature material was found or no key id information could be found (V4SignatureMaterial).
     */
    public byte[] getKeyID() throws AlgorithmException {
        if (getSignatureData() == null)
            throw new AlgorithmException("No signature material found");
        
        return getSignatureData().getKeyID();
    }

    /** 
     * <p>Verify the signature material against the signer's public key by calling the verify method
     * on the registered SignatureMaterial object.</p>
     * @param signersKey The public key belonging to the signer of the packet.
     * @param data[] The data to verify against.
     * @return true if the signature is valid, false if not.
     * @throws AlgorithmException if something went wrong.
     */
    public boolean verify(PublicKey signersKey, byte data[]) throws AlgorithmException {
        if (getSignatureData() == null)
            throw new AlgorithmException("No signature material found");
        
        return getSignatureData().verify(signersKey, data);
    }
  
    /** Return the raw signature material. */
    public SignatureMaterial getSignatureData() {
        return data;
    }
    
    /** Set the signature material data */
    protected void setSignatureData(SignatureMaterial material) {
        data = material;
    }
    
    /**
     * <p>A method constructs a packet out of raw binary data.</p>
     * <p>You should implement this in all your packets. If a packet is a container packet
     * you must also populate the subpackets vector by extracting and constructing the relevent packets.</p>
     * @param data[] The packet body data as a raw binary bytestream. If you are using OpenPGPPacketInputStream the header will automatically be created for you.
     * @throws AlgorithmException if there was a problem.
     */
    public void buildPacket(byte[] data) throws AlgorithmException {
        try {
            ByteArrayInputStream in = new ByteArrayInputStream(data);
            
            setVersion(in.read());
            
            switch (getVersion()) {
                case 3 : setSignatureData(new V3SignatureMaterial()); break;
                case 4 : setSignatureData(new V4SignatureMaterial()); break;
                default : throw new AlgorithmException("Bad signature packet version ("+getVersion()+")");
            }
            
            getSignatureData().build(in);
            
        } catch (Exception e) {
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
            
            out.write(getVersion() & 0xff);
            
            out.write(getSignatureData().encode());
            
            return out.toByteArray();
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
}
