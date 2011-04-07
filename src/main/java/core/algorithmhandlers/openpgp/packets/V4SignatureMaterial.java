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
import core.exceptions.openpgp.*;
import core.algorithmhandlers.openpgp.packets.v4signature.*;
import java.util.*;
import java.io.*;
import java.security.*;

/**
 * <p>Implements a V4 signature packet.</p>
 */
public class V4SignatureMaterial extends SignatureMaterial {
    
    /** Hashed sub packets */
    private Vector hashedSubPackets;
    
    /** Unhashed sub packets */
    private Vector unhashedSubPackets;

    
    /** Create a new instance of V4SignatureMaterial suitable for construction with the build method.*/
    public V4SignatureMaterial() {
        hashedSubPackets = new Vector();
        unhashedSubPackets = new Vector();
    }
    
    /** <p>Create a new instance of V4SignatureMaterial.</p>
     * <p>The constructor adds a creation time sub packet, a issuer key id sub packet and a signature expiration time sub packet. The latter only being added 
     * if expiry is greater than 0.</p>
     * @param key The private key to sign the packet with.
     * @param expiry The length of time from now this signature is valid for, usually this should be 0. If it is 0, no sub packet is created as 0 is implied by the absense.
     * @param keyID[] The 8 byte key id of the signing key (as calculated by the appropriate AsymmetricAlgorithmParameters method).
     * @param sigType The type of signature this is.
     * @param keyalgorithm The type of public key algorithm to use to sign data with.
     * @param hashalgorithm The type of hash algorithm to use.
     * @param data[] The data to sign (the encoded packet data).
     * @throws AlgorithmException if signature could not be created for whatever reason.
     */
    public V4SignatureMaterial(PrivateKey key, long expiry, byte keyID[], int sigType, int keyalgorithm, int hashalgorithm, byte data[]) throws AlgorithmException {
        
    	setSignatureType(sigType);
        addHashedSubPacket(new SignatureCreationTimeSubPacket()); // creation time
        if (expiry>0) // expiry
            addHashedSubPacket(new SignatureExpirationTimeSubPacket(expiry)); 
        setPublicKeyAlgorithm(keyalgorithm);
        setHashAlgorithm(hashalgorithm);
        
        setKeyID(keyID);
        sign(key, data); // sign and generate hash
    }
    
    /** <p>Add a sub packet to the end of the hashed packet list.</p>
     * <p>IMPORTANT: If you add a hashed packet you MUST re-sign the packet!</p>
     */
    public void addHashedSubPacket(SignatureSubPacket packet) {
        if (hashedSubPackets == null)
            hashedSubPackets = new Vector();
        
        hashedSubPackets.addElement(packet);
    }
    
    /** Add a sub packet to the end of the unhashed packet list */
    public void addUnhashedSubPacket(SignatureSubPacket packet) {
        if (unhashedSubPackets == null)
            unhashedSubPackets = new Vector();
        
        unhashedSubPackets.addElement(packet);
    }
    
    /** Return a vector containing all the sub packets in the hashed list. */
    public Vector getHashedSubPackets() {
        return hashedSubPackets;
    }
    
    /** Return a vector containing all the sub packets in the unhashed list. */
    public Vector getUnhashedSubPackets() {
        return unhashedSubPackets;
    }
        
    /**
     * <p>Retrieve the key ID data.</p>
     * <p>Key IDs are stored in a slightly different way depending on the version of the packet.
     * With V4 keys it is possible (although unlikely) that there is no key ID stored.</p>
     * @throws AlgorithmException if the key id could not be retrieved for whatever reason.
     */
    public byte[] getKeyID() throws AlgorithmException {

        // look for keyID in hashed material first
        for (int n = 0; n < hashedSubPackets.size(); n++) {
            if (hashedSubPackets.elementAt(n) instanceof IssuerKeyIDSubPacket) {
                IssuerKeyIDSubPacket id = (IssuerKeyIDSubPacket)hashedSubPackets.elementAt(n);         
                return id.getKeyID();
            }       
        }
        
        // couldn't find in the hashed material, now look in the unhashed stuff
        for (int n = 0; n < unhashedSubPackets.size(); n++) {
            if (unhashedSubPackets.elementAt(n) instanceof IssuerKeyIDSubPacket) {
                IssuerKeyIDSubPacket id = (IssuerKeyIDSubPacket)unhashedSubPackets.elementAt(n);
                return id.getKeyID();
            }       
        }
        
        // if we got here then we couldn't find a key ID packet in the hashed or unhashed material
        throw new AlgorithmException("Unable to find a key ID packet in signature material"); 
    }
    
    /**
     * <p>Set the key ID.</p>
     * <p>V4 signatures store this information as a sub packet.</p>
     * <p>The issuer key id packet is currently added as unhashed as this appears to be the standard.</p>
     * @throws AlgorithmException if the key id could not be set for whatever reason.
     */
    protected void setKeyID(byte[] id) throws AlgorithmException {
        addUnhashedSubPacket(new IssuerKeyIDSubPacket(id));
    }
        
    /** 
     * <p>Read a sub packet from a byte stream.</p>
     * <p>This method reads through and constructs sub packets in much the same way as OpenPGPPacketInputStream
     * constructs normal packets.</p>
     * <p>As according to the RFC unknown packets in the stream are quietly ignored.</p>
     * @param in An input stream.
     * @throws IOException if there was a problem reading the packet data.
     * @throws UnrecognisedSignatureSubPacketException if a packet type was unrecognised. According to the spec these should be ignored. If this exception is thrown, a whole packet has been read and the stream is in the correct position to read the next packet.
     * @throws UnrecognisedCriticalSignatureSubPacketException if a packet type was unrecognised and was marked as critical. Note, this is a child of UnrecognisedSignatureSubPacketException and should be looked for first if you want to ignore the non fatal error. 
     * Also if this exception is thrown, a whole packet has been read and the stream is in the correct position to read the next packet.
     * @return A constructed SignatureSubPacket.
     */
    protected SignatureSubPacket readSubPacket(InputStream in) throws UnrecognisedSignatureSubPacketException, UnrecognisedCriticalSignatureSubPacketException, IOException {
        SignatureSubPacketHeader header = new SignatureSubPacketHeader(in);
        SignatureSubPacket packet = null;
        
        switch (header.getType()) {

            case 2 : packet = new SignatureCreationTimeSubPacket(); break; 
            case 3 : packet = new SignatureExpirationTimeSubPacket(); break; 
            case 4 : packet = new ExportableCertification(); break;
            case 5 : packet = new TrustSignatureSubPacket(); break;
            case 6 : packet = new RegularExpressionSubPacket(); break;
            case 7 : packet = new RevocableSubPacket(); break;
            case 9 : packet = new KeyExpirationTimeSubPacket(); break; 
            case 11 : packet = new PreferredSymmetricAlgorithmSubPacket(); break; 
            case 12 : packet = new RevocationKeySubPacket(); break;
            case 16 : packet = new IssuerKeyIDSubPacket(); break; 
            case 20 : packet = new NotationDataSubPacket(); break;
            case 21 : packet = new PreferredHashAlgorithmSubPacket(); break; 
            case 22 : packet = new PreferredCompressionAlgorithmSubPacket(); break; 
            case 23 : packet = new KeyServerPreferencesSubPacket(); break;
            case 24 : packet = new PreferredKeyServerSubPacket(); break;
            case 25 : packet = new PrimaryUserIDSubPacket(); break;
            case 26 : packet = new PolicyURLSubPacket(); break;
            case 27 : packet = new KeyFlagsSubPacket((int)header.getBodyLength()); break;
            case 28 : packet = new SignersUserIDSubPacket(); break;
            case 29 : packet = new ReasonForRevocationSubPacket(); break;
            case 30 : packet = new FeaturesSubPacket(); break;
            case 31 : packet = new SignatureTargetSubPacket(); break;
            case 32 : packet = new EmbeddedSignatureSubPacket(); break;
            case 100 : case 101 : case 102 : case 103 : case 104 : 
            case 105 : case 106 : case 107 : case 108 : case 109 :
            case 110 : packet = new PlaceholderSubPacket(); break;

            default : if (header.isCritical())
                throw new UnrecognisedCriticalSignatureSubPacketException("Unrecognised critical v4 Signature sub-packet. Signature is likely to be invalid.");
            else
                throw new UnrecognisedSignatureSubPacketException("Unrecognised v4 Signature sub-packet.");
        }

        // bind packet header
        packet.setSubPacketHeader(header);
        
        // read full packet
        byte data[] = new byte[(int)header.getBodyLength()];
        in.read(data);
        packet.decode(data);

        return packet;
    }
    
    /**
     * <p>Write a sub packet to a byte stream.</p>
     * <p>This method writes packets in much the same way as OpenPGPPacketOutputStream.</p>
     * @param packet The sub packet to write.
     * @param out An output stream.
     * @throws IOException if something went wrong writing the packet.
     */
    protected void writeSubPacket(SignatureSubPacket packet, OutputStream out) throws IOException {
        packet.encode(out);
    }
 
    /** Parse sub packets from a byte stream.
     * @param in Stream containing sub packets (without scailer size)
     * @param size Number of bytes of sub-packets to read from stream
     * @param hashed Am i reading hashed packets or not.
     * @throws IOException if the data could not be parsed from the stream.
     */
    protected void parseSubPackets(InputStream in, int size, boolean hashed) throws IOException {
        
        byte [] data = new byte[size];
        in.read(data);
        ByteArrayInputStream packets = new ByteArrayInputStream(data);
        
        while (packets.available() > 0) {
            try {
                if (hashed) 
                    addHashedSubPacket(readSubPacket(packets));
                else
                    addUnhashedSubPacket(readSubPacket(packets));
            } catch (UnrecognisedSignatureSubPacketException e) { // catch and ignore both critical and not critical exceptions... there may be useful packets left in the stream                    
            }
        }
    }
    
    /** Utility method used to encode all sub packets in a given vector to a byte stream.
     * @param hashed Encode hashed sub packet vector (true) or unhashed (false).
     * @return A byte array containing a 2 byte scailer length followed by the packet data.
     * @throws IOException if the data couldn't be serialised.
     */
    protected byte [] encodeSubPackets(boolean hashed) throws IOException {
        
        Vector packets = null;
        
        if (hashed) {
            packets = hashedSubPackets;
        } else {
            packets = unhashedSubPackets;
        }
        
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        
        if ((packets != null) && (packets.size() > 0)) {
            // serialise packets
            ByteArrayOutputStream tmp = new ByteArrayOutputStream();
            
            for (int n = 0; n < packets.size(); n++) {
                writeSubPacket((SignatureSubPacket)packets.elementAt(n), tmp);
            }
            
            // write scalar (full size of encoded data) 
            out.write((tmp.toByteArray().length >> 8) & 0xff);
            out.write(tmp.toByteArray().length & 0xff);

            // write sub packets
            out.write(tmp.toByteArray());
            
        } else { // data is empty, so write zero length
            // write scalar (full size of encoded data) 
            out.write((0 >> 8) & 0xff);
            out.write(0 & 0xff);
        }
        
        return out.toByteArray();  
    }
    
    /**
     * <p>Construct the signature material out of an input stream.</p>
     * @throws AlgorithmException if something goes wrong.
     */
    public void build(InputStream in) throws AlgorithmException {
    	
        try {
            // read signature type
            setSignatureType(in.read());
            
            // public key algorithm
            setPublicKeyAlgorithm(in.read());
            
            // hash algorithm
            setHashAlgorithm(in.read());
            
            // Read hashed sub packets
            // Read scalar (full size of encoded data) - read in that amount of bytes and read packets from that
            int hashedScalar = ((in.read() & 0xff) << 8) | (in.read() & 0xff);
            // read hashed sub packets
            parseSubPackets(in, hashedScalar, true);

            // Read unhashed sub packets
            // Read scalar (full size of encoded data) - read in that amount of bytes and read packets from that
            int unhashedScalar = ((in.read() & 0xff) << 8) | (in.read() & 0xff);
            // read unhashed sub packets
            parseSubPackets(in, unhashedScalar, false);
            
            // hash
            setHash(((in.read() & 0xFF ) << 8) | (in.read() & 0xFF));
            
            // encoded signature data
            byte sigdata[] = new byte[in.available()];
            in.read(sigdata);
            setSignature(sigdata);
            
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }    
    }
     
    /**
     * <p>Encode the signature material and return it as a byte array.</p>
     * @throws AlgorithmException if something goes wrong.
     */
    public byte[] encode() throws AlgorithmException {
        try {
                  
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            
            out.write(getSignatureType() & 0xff);
            
            out.write(getPublicKeyAlgorithm() & 0xff);
            
            out.write(getHashAlgorithm() & 0xff);
            
            // write hashed packets 
            out.write(encodeSubPackets(true));    
            
            // write unhashed packets 
            out.write(encodeSubPackets(false));    
            
            out.write((getHash() >> 8) & 0xff);
            out.write(getHash() & 0xff);
  
            out.write(getSignature());

            return out.toByteArray();
            
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
    /**
     * <p>A utility method used to construct the raw data used in the signature algorithm.</p>
     * @param data[] The initial data used in the calculation, i.e. the data you're signing.
     * @return a byte array containing the raw signature data.
     * @throws AlgorithmException if something went wrong.
     */
    protected byte[] calculateRawSigData(byte[] data) throws AlgorithmException {
         try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();  
            ByteArrayOutputStream body = new ByteArrayOutputStream();  

            // write data
            out.write(data);
            
            // version is always 4
            body.write(4 & 0xff);
            body.write(getSignatureType() & 0xff);
            body.write(getPublicKeyAlgorithm() & 0xff);
            body.write(getHashAlgorithm() & 0xff);
            body.write(encodeSubPackets(true));
            
            out.write(body.toByteArray());    
            
            out.write(0x04);
            out.write(0xff);
            out.write((byte)(body.toByteArray().length >> 24));
            out.write((byte)(body.toByteArray().length >> 16));
            out.write((byte)(body.toByteArray().length >> 8));
            out.write((byte)body.toByteArray().length);

            return out.toByteArray();
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
}
