package core.algorithmhandlers.openpgp.packets;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import core.exceptions.AlgorithmException;

/**
 * The Modification Detection Code Packet contains a SHA-1 hash of plaintext
 * data which is used to detect message modification. It is only used with a
 * Symmetrically Encrypted Integrity Protected Data packet. The Modification
 * Detection Code packet MUST be the last packet in the plaintext data which
 * is encrypted in the Symmetrically Encrypted Integrity Protected Data packet,
 * and MUST appear in no other place.
 */
public class ModificationDetectionCodePacket extends Packet {
	
	public final static int SIZE = 22; // fixed size - includes header

	/** 
	 * 20-byte SHA-1 digest of the preceding plaintext data of the 
	 * symmetrically encrypted integrity protected data packet, including
	 * prefix data, the header tag octet, and the header length octet of the
	 * Modification Detection Code Packet.
	 */
    private byte digest[];
    
    /** Creates a new instance of ModificationDetectionCodePacket.
     * @throws AlgorithmException if the packet could not be created.
     */
    public ModificationDetectionCodePacket() throws AlgorithmException {
        setPacketHeader(new PacketHeader(19, true, 20));
    }
    
	/**
	 * @see core.algorithmhandlers.openpgp.packets.Packet#buildPacket(byte[])
	 */
	public void buildPacket(byte[] data) throws AlgorithmException {
		digest = data;
		if (data.length != 20) {
			throw new AlgorithmException("Invalid ModificationDetectionCodePacket " +
					"data length");
		}
	}

	/**
	 * @see core.algorithmhandlers.openpgp.packets.Packet#encodePacket()
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
	 * @see core.algorithmhandlers.openpgp.packets.Packet#encodePacketBody()
	 */
	public byte[] encodePacketBody() throws AlgorithmException {
		try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            
            out.write(digest);
        
            return out.toByteArray();
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
	}

}
