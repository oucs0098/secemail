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
import core.algorithmhandlers.openpgp.util.*;
import core.exceptions.AlgorithmException;
import org.bouncycastle.jce.provider.*;
import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * <p>A symetrically encrypted container.</p>
 * <p>This packet contains other pgp packets and encrypts them. This packet provides the main body
 * of a pgp message.</p>
 * <p>The class is given a session key which can be obtained from a previous public / symetric encrypted session key packet, or the MD5 hash of 
 * a passphrase.</p>
 * <p>Note: This container DOES NOT automatically unpack sub packets into a readable form for security reasons. 
 * You must encode and decode contained packets EXPLICITLY using the appropriate decrypt / encrypt methods and provide the appropriate session keys.</p>
 * <p><b>IMPORTANT NOTE:</b> As with the CompressedDataPacket, unless this packet is loaded from a stream _and_ no calls to add() have been made, the PacketHeader's length type and bodylength tags
 * are MEANINGLESS! It is not possible to accurately calculate the size of the body before it is encoded. Therefore this class'
 * encodePacket() method recalculates the header length information. 
 */
public class SymmetricallyEncryptedDataPacket extends EncryptedDataPacket {
    
    /** The encrypted encoded form of the packet populated by buildPacket. Also contains OpenPGPs weird IValike thingy. */
    private byte rawData[];
    
    /** Creates a new instance of SymmetricallyEncryptedDataPacket. Since this method is the same for both stream construction and manual construction
     * this method DOES generate a header, but with no size information (see class documentation for the reason).
     */
    public SymmetricallyEncryptedDataPacket() throws AlgorithmException {
        setPacketHeader(new PacketHeader(9, false));
    }
    
    /** 
     * <p>Decrypt the raw encoded data.</p>
     * <p>This method will attempt to decode the raw data and populate the internal array of packets that can be read using the unpack method.</p>
     * <p>You should call this method on the packet after reading it in from a stream in order to get access to its sub packets.</p>
     * @throws AlgorithmException if something went wrong, most likely that the wrong session key was used.
     */
    public void decryptAndDecode(SessionKey sessionkey) throws AlgorithmException {
        
        try {
            // the blocksize
            int blockSize = SymmetricAlgorithmSettings.getDefaultBlockSize(sessionkey.getAlgorithm())/8;
            
            // convert session key to keyspec
            SecretKey key = new SecretKeySpec(sessionkey.getSessionKey(), SymmetricAlgorithmSettings.getCipherText(sessionkey.getAlgorithm()));
            
            // create cipher (IV is not required)
            Cipher cipher = Cipher.getInstance(SymmetricAlgorithmSettings.getFullCipherText(sessionkey.getAlgorithm()),"BC");
            cipher.init(Cipher.DECRYPT_MODE, key);
                        
            // decrypt and construct packets (an exception thrown here will likely denote the wrong key was used)
            buildMultiplePackets(cipher.doFinal(rawData));

        } catch (Exception e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
    /**
	 * @see core.algorithmhandlers.openpgp.packets.EncryptedDataPacket#encryptAndEncode(SessionKey)
	 */
    public void encryptAndEncode(SessionKey sessionkey) throws AlgorithmException {

        try {
            // the blocksize
            int blockSize = SymmetricAlgorithmSettings.getDefaultBlockSize(sessionkey.getAlgorithm())/8;
            
            // convert session key to keyspec
            SecretKey key = new SecretKeySpec(sessionkey.getSessionKey(), SymmetricAlgorithmSettings.getCipherText(sessionkey.getAlgorithm()));
            
            // create IV
            byte[] ivdata = new byte[blockSize];
            SecureRandom rnd = SecureRandom.getInstance("SHA1PRNG");
            rnd.nextBytes(ivdata);
            IvParameterSpec iv = new IvParameterSpec(ivdata);
            
            // create cipher
            Cipher cipher = Cipher.getInstance(SymmetricAlgorithmSettings.getFullCipherText(sessionkey.getAlgorithm()),"BC");
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);

            rawData = cipher.doFinal(encodeMultiplePackets());
    
        } catch (Exception e) {
            throw new AlgorithmException(e.getMessage());
        }
              
    }
    
    /**
     * <p>A method constructs a packet out of raw binary data.</p>
     * <p>You should implement this in all your packets. If a packet is a container packet
     * you must also populate the subpackets vector by extracting and constructing the relevent packets.</p>
     * @param data[] The packet body data as a raw binary bytestream. If you are using OpenPGPPacketInputStream the header will automatically be created for you.
     * @throws AlgorithmException if there was a problem.
     */
    public void buildPacket(byte[] data) throws AlgorithmException {
        rawData = data; // store in encoded + encrypted form
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

            setPacketHeader(new PacketHeader(9, false, encodePacketBody().length)); 
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

            out.write(rawData);

            return out.toByteArray();
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
}
