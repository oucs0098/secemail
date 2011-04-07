package core.algorithmhandlers.openpgp.packets.v4signature;

import java.io.IOException;
import java.io.OutputStream;

import core.exceptions.AlgorithmException;

/** <p>Describes a 'notation' on the signature that the issuer wishes to make.</p> */
public class NotationDataSubPacket extends FlagsSubPacket {
    
	/** Human readable flag. The only flag defined. */
    public static final int HUMAN_READABLE = 0x80;
    
    /** Notation name, a UTF-8 string stored in a byte array */
    private byte name[];
    
    /** Notation value, a UTF-8 string stored in a byte array */
    private byte value[];
    
    /** Creates a new instance of NotationDataSubPacket */
    public NotationDataSubPacket() {
        super(4);
        setFlag(0, HUMAN_READABLE, true);  // other flags are undefined
    }
    
    /** Creates a new instance of NotationDataSubPacket 
     * @param nameLength The length of the name, from the packet
     * @param valueLength The length of the value, from the packet
     * @param name The notation name
     * @param value The notation value
     */
    public NotationDataSubPacket(int nameLength, byte[] name, int valueLength, 
    		byte[] value) throws AlgorithmException {
        super(4);
        setFlag(0, HUMAN_READABLE, true);  // other flags are undefined
        
        if (nameLength != name.length)
        	throw new AlgorithmException("Name lengths do not match");
        setName(name);
        
        if (valueLength != value.length)
        	throw new AlgorithmException("Value lengths do not match");
        setValue(value);
    }

	/** Gets the notation name
	 * @return the name
	 */
	public byte[] getName() {
		return name;
	}

	/** Sets the notation name
	 * @param name the name to set
	 */
	public void setName(byte[] name) {
		this.name = name;
	}

	/** Gets the notation value
	 * @return the value
	 */
	public byte[] getValue() {
		return value;
	}

	/** Sets the notation value
	 * @param value the value to set
	 */
	public void setValue(byte[] value) {
		this.value = value;
	}
	
	/** Returns true if the NO_MODIFY flag has been set. */
    public boolean getHumanReadableFlag() {
        return getFlag(0, HUMAN_READABLE);
    }
    
    /** Set the NO_MODIFY flag.
     * @param set Toggle the flag on (true) or off (false).
     */
    public void setHumanReadableFlag(boolean set) {
        setFlag(0, HUMAN_READABLE, set);
    }
	
	/** <p>Construct a packet from a preloaded data array.</p>
     * <p>This method allows the V4SignatureMaterial class to read a full packet
     * in before processing, allowing the read method to better handle unknown 
     * packets.</p>
     * @param data[] The full packet.
     * @throws IOException if something went wrong.
     */
    public void decode(byte[] data) throws IOException {
        
        super.decode(data);
        
        setFlag(0, data[0] & 0xff, true);
        setFlag(1, data[1] & 0xff, true);
        setFlag(2, data[2] & 0xff, true);
        setFlag(3, data[3] & 0xff, true);
        
        int nameLength = ((data[4] & 0xff) << 8) + (data[5] & 0xff);
        int valueLength = ((data[6] & 0xff) << 8) + (data[7] & 0xff);
        
        byte[] name = new byte[nameLength];
        byte[] value = new byte[valueLength];
        
        System.arraycopy(data, 8, name, 0, nameLength);
        System.arraycopy(data, nameLength+8, value, 0, valueLength);
        
        setName(name);
        setValue(value);
    }    
    
    /** <p>Write the packet (with header) out to a byte stream.</p>
     * @throws IOException if something went wrong.
     */
    public void encode(OutputStream out) throws IOException {
    	getSubPacketHeader().encode(out);
    	
        out.write(getDataElement(0) & 0xff);
        out.write(getDataElement(1) & 0xff);
        out.write(getDataElement(2) & 0xff);
        out.write(getDataElement(3) & 0xff);
        
        out.write((getName().length >> 8) & 0xff);
        out.write(getName().length & 0xff);
        out.write((getValue().length >> 8) & 0xff);
        out.write(getValue().length & 0xff);
        
        out.write(getName());
        out.write(getValue());
    }
}
