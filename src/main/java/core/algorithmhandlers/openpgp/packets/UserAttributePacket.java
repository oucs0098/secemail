package core.algorithmhandlers.openpgp.packets;

import core.algorithmhandlers.openpgp.packets.userattribute.*;
import core.exceptions.AlgorithmException;
import core.exceptions.openpgp.UnrecognisedUserAttributeSubPacketException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.util.Vector;
import java.util.Iterator;

/**
 * <p>A packet representing a user attribute.</p>
 * <p>This packet is a variation on the user ID packet, and as of this writing 
 * this packet can only contain one type of subpacket, the image attribute subpacket.</p>
 */
public class UserAttributePacket extends Packet
{
	/** Hashed sub packets */
    private Vector attributeSubPackets;
    
    /** Generic constructor.*/
    public UserAttributePacket() {
    	attributeSubPackets = new Vector();
    }
    
	/** Return a vector containing all the sub packets in the unhashed list. */
	public Vector getAttributeSubPackets() {
		return attributeSubPackets;
	}
    
	/** <p>This method constructs a packet out of raw binary data.</p> */
	public void buildPacket(byte[] data) throws AlgorithmException {
		int offset = 0;
		int length = data.length;
		InputStream in = new ByteArrayInputStream(data);
		try {
			while(offset < length) {
				UserAttributeSubPacketHeader header = 
						new UserAttributeSubPacketHeader(in);
		    	UserAttributeSubPacket subPacket = null;
		        
				switch (header.getSubPacketType()) {
				    case 1 : subPacket = new ImageAttributeSubPacket(); break;
				    default : // According to RFC other types should be ignored.
				    	throw new UnrecognisedUserAttributeSubPacketException(
				    			"Unrecognised User Attribute Sub-packet type " + 
				    			header.getSubPacketType());
				}

		        // bind packet header
				subPacket.setSubPacketHeader(header);
		        
		        // read full packet
		        byte spdata[] = new byte[(int)header.getSubPacketBodyLength()-1];
		        in.read(spdata);
		        subPacket.decode(spdata);
		        
				attributeSubPackets.add(subPacket);
				offset += subPacket.getSubPacketHeader().getSubPacketLength();
			}
		} catch( IOException ignore ) {}
	}

	/** <p>This method produces a straight binary representation of this packet.</p> */
	public byte[] encodePacket() throws AlgorithmException
	{
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();

			out.write(getPacketHeader().encodeHeader());
			out.write(encodePacketBody());

			return out.toByteArray();
		} catch(IOException e) {
			throw new AlgorithmException( e.getMessage() );
		}
	}

	/** <p>This method produces a straight binary representation of this packet's
	 * body.</p>
     */
	public byte[] encodePacketBody() throws AlgorithmException
	{
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			Iterator iter = attributeSubPackets.iterator();

			while (iter.hasNext()) {
				UserAttributeSubPacket subPacket = 
						(UserAttributeSubPacket)iter.next();
				subPacket.encode(out);
			}

			return out.toByteArray();
		} catch(IOException e) {
			throw new AlgorithmException(e.getMessage());
		}
	}
}
