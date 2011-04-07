package core.algorithmhandlers.openpgp.packets.userattribute;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/** <p>A header class for use with user attribute sub packets.</p> */
public class UserAttributeSubPacketHeader
{
	/** The subpacket type. */
	private int subPacketType;
	
	/** The subpacket length. */
	private long subPacketLength;
	
	/** The body length. */
	private long subPacketBodyLength;
    
	/** Get the length of the subpacket. */
    public long getSubPacketLength() {
		return subPacketLength;
	}
    
    /** Get the length of the subpacket body. */
    public long getSubPacketBodyLength() {
		return subPacketBodyLength;
	}

    /** Get the type of the subpacket. */
	public int getSubPacketType() {
		return subPacketType;
	}

	/** Creates a new instance of SignatureSubPacketHeader from type and 
	 * length fields.
	 */
	public UserAttributeSubPacketHeader(int subPacketType, long length) {
		this.subPacketType = subPacketType;
		this.subPacketLength = length;
	}
	
	/** Creates a new instance of SignatureSubPacketHeader from a stream. */
	public UserAttributeSubPacketHeader(InputStream in) throws IOException {
		decode(in);
	}
	
	/** 
	 * Encode the packet header out to an output stream. 
	 * @param out Output stream to use.
	 * @throws IOException if something went wrong.
	 */ 
	public void encode(OutputStream out) throws IOException {
		if (subPacketBodyLength < 192) {
            out.write((byte)(subPacketBodyLength & 0xff));
        } else if (subPacketBodyLength < 4294967296L) {
            out.write(255); 
            out.write((byte)(subPacketBodyLength >> 24));
            out.write((byte)(subPacketBodyLength >> 16));
            out.write((byte)(subPacketBodyLength >> 8));
            out.write((byte)(subPacketBodyLength));
        } else if (subPacketBodyLength < 16320) {
        	/* 
        	 * user attribute subpackets created by PGP use the 1 or 5-byte 
        	 * format, and since they are used for hashing with a signature, 
        	 * consistency is the watchword. So this section will never be 
        	 * reached for now (it'd be easy to move it back between the 
        	 * previous two clauses though PGP-originated user attributes may
        	 * stop validating) 
        	 */
			out.write((byte)(((subPacketBodyLength - 192) >> 8) + 192));
			out.write((byte)(subPacketBodyLength - 192));
        }
		
		// write type
        out.write(getSubPacketType() & 0xff);
	}
	
	/** Decode the packet header from an input stream.
	 * @param in Input stream to use.
	 * @throws IOException if something went wrong.
	 */ 
	public void decode(InputStream in) throws IOException {
		// read length
		int headerLength = 0;
		int lengthType = in.read();
		if (lengthType < 192) {
			subPacketBodyLength = lengthType;
			headerLength++;
		} else if ((lengthType >= 192) && (lengthType < 255)) {
			subPacketBodyLength = ((lengthType - 192) << 8) + (in.read() & 0xff) + 192;
			headerLength += 2;
		} else if(lengthType == 255) {
			subPacketBodyLength = (
				( (in.read() & 0xff) << 24) +
				( (in.read() & 0xff) << 16) +
				( (in.read() & 0xff) << 8) +
				( in.read() & 0xff )
			);
			headerLength += 5;
		}
		
		// read type
		int typeoctet = in.read() & 0xff;
		subPacketType = typeoctet & 0x7f;
		headerLength++;
		this.subPacketLength = this.subPacketBodyLength + headerLength;
	}
}
