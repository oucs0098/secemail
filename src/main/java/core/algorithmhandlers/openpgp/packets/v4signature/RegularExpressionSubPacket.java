package core.algorithmhandlers.openpgp.packets.v4signature;

import java.io.IOException;
import java.io.OutputStream;

/** A sub packet that holds a regular expression, used in conjunction with
 * trust signature packets (of level > 0) to limit the scope of trust that
 * is extended. Only signatures by the target key on user IDs that match 
 * the regular expression have trust extended by the trust signature subpacket.
 * @see RFC2440
 */
public class RegularExpressionSubPacket extends SignatureSubPacket {

	/** Regular expression. */
    private byte regularExpression[];
    
    /** Creates a new instance of RegularExpressionSubPacket */
    public RegularExpressionSubPacket() {
    }
    
    /** Creates a new instance of RegularExpressionSubPacket and sets the regular 
     * expression
     * @param regexp null-terminated regular expression, as described in RFC2440
     */
    public RegularExpressionSubPacket(byte[] regexp) {
        this.regularExpression = regexp;
        setSubPacketHeader(new SignatureSubPacketHeader(6, false, regexp.length + 1));
    }
    
    /** <p>Construct a packet from a preloaded data array.</p>
     * <p>This method allows the V4SignatureMaterial class to read a full packet 
     * in before processing, allowing
     * the read method to better handle unknown packets.</p>
     * @param data[] The full packet.
     * @throws IOException if something went wrong.
     * @see core.algorithmhandlers.openpgp.packets.v4signature.SignatureSubPacket#decode(
	 * byte[]) 
	 */
	public void decode(byte[] data) throws IOException {
		regularExpression = data;
	}

	/** <p>Write the packet, with preceding header and terminating null byte, 
     * out to a byte stream.</p>
     * @throws IOException if something went wrong.
     * @see core.algorithmhandlers.openpgp.packets.v4signature.SignatureSubPacket#encode(
     * java.io.OutputStream)
     */
	public void encode(OutputStream out) throws IOException {
		getSubPacketHeader().encode(out);
        out.write(regularExpression);  // null byte should be included in byte array
	}

	/** Returns the regular expression
	 * @return the regular expression
	 */
	public byte[] getRegularExpression() {
		return regularExpression;
	}

	/** Sets the regular expression (the byte array must include a null-terminating
	 * byte)
	 * @param regularExpression the regular expression to set
	 */
	public void setRegularExpression(byte[] regularExpression) {
		this.regularExpression = regularExpression;
	}
}
