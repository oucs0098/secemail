package core.algorithmhandlers.openpgp.packets.userattribute;

import java.io.IOException;
import java.io.OutputStream;

/**
 * <p>This subpacket is used to encode an image, presumably (but not required
 * to be) that of the key owner.</p>
 */
public class ImageAttributeSubPacket extends UserAttributeSubPacket
{
	/** The image header length (16 octets for V1 header) */
	private int imageHeaderLength;
	
	/** The image header version (V1 (1) is the only one currently defined) */
	private int imageHeaderVersion;
	
	/** The image encoding format, only format currently defined = 1 (JPEG) */
	private int imageEncodingFormat;
	
	/** Extra info, received in packets, normally set to 0 for new subpackets,
	 * has to be preserved because signature verification relies on the 
	 * integrity of the image header as well as image data and public key.
	 */
	private byte[] padding;
	
	/** The raw image data */
	private byte[] imageData;
	
	/** Creates a new instance of ImageAttributeSubPacket with defaults */
	public ImageAttributeSubPacket() {
		this.imageHeaderLength = 16; // According to image header V1
		this.imageHeaderVersion = 1; // Only V1 currently exists
		this.imageEncodingFormat = 1; // JPEG/JFIF
		this.padding = new byte[12];
	}
    
	/** Gets the image data
	 * @return The raw image data
	 */
	public byte[] getImageData() {
		return imageData;
	}

	/** Sets the image data
	 * @param imageData The raw image data
	 */
	public void setImageData(byte[] imageData) {
		this.imageData = imageData;
	}
	
	/** <p>Construct a packet from a preloaded data array.</p>
     * <p>This method allows the UserAttributePacket class to read a full 
     * packet in before processing, allowing the read method to better handle
     * unknown packets.</p>
     * @param data[] The full packet.
     * @throws IOException if something went wrong.
     */
	public void decode(byte[] data) throws IOException {
		// header length is stored as a little-endian two-octet number ...
		this.imageHeaderLength = (data[0] & 0xff) + ((data[1] & 0xff) << 8 );
		this.imageHeaderVersion = (data[2] & 0xff);
		this.imageEncodingFormat = (data[3] & 0xff);
		this.padding = new byte[this.imageHeaderLength - 4];
		System.arraycopy(data, 4, this.padding, 0, this.imageHeaderLength - 4);
		int imageLength = data.length - this.imageHeaderLength;
		this.imageData = new byte[imageLength];
		System.arraycopy(data, this.imageHeaderLength, this.imageData, 0, imageLength);
	}

	/**
     * <p>Write the packet (with header) out to a byte stream.</p>
     * @throws IOException if something went wrong.
     */
	public void encode(OutputStream out) throws IOException {
		getSubPacketHeader().encode(out);
		
		out.write((byte)this.imageHeaderLength);
		out.write((byte)this.imageHeaderLength >> 8);
		out.write((byte)this.imageHeaderVersion);
		out.write((byte)this.imageEncodingFormat);
		out.write(this.padding);
		out.write(this.imageData);
	}
}
