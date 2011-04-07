package core.algorithmhandlers.openpgp.packets.userattribute;

import java.io.IOException;
import java.io.OutputStream;

/**
 * <p>Root class for all user attribute sub packets. </p>
 */
public abstract class UserAttributeSubPacket
{
	/** The packet header. */
    private UserAttributeSubPacketHeader header;

    /**
     * Get the sub packet header.
     */
	public UserAttributeSubPacketHeader getSubPacketHeader()
	{
		return header;
	}

	/**
     * Set the sub packet header.
     */
	public void setSubPacketHeader( UserAttributeSubPacketHeader header )
	{
		this.header = header;
	}
	
	/** 
     * <p>Write the packet (with header) out to a byte stream.</p>
     * @throws IOException if something went wrong.
     */
    public abstract void encode(OutputStream out) throws IOException;
    
    /**
     * <p>Construct a packet from a preloaded data array.</p>
     * <p>This method allows the UserAttributePacket class to read a full packet
     * in before processing, allowing the read method to better handle unknown 
     * packets.</p>
     * @param data[] The full packet.
     * @throws IOException if something went wrong.
     */
    public abstract void decode(byte data[]) throws IOException;
    
}
