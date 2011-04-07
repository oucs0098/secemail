package core.algorithmhandlers.openpgp.packets.v4signature;

/** <p>Information (flags) relating to key holder's implementation's supported 
 * features.</p>
 */
public class FeaturesSubPacket extends FlagsSubPacket {

	/** The key holder's implementation supports the modification detection packets
	 * (packets 18 and 19). 
	 */
    public static final int SUPPORTS_MODIFICATION_DETECTION = 0x01;

    /** Creates a new instance of FeaturesSubPacket */
    public FeaturesSubPacket() {
    }
    
    /** Creates a new instance of FeaturesSubPacket 
     * @param numflags Number of flag bytes.
     */
    public FeaturesSubPacket(int numflags) {
        super(numflags);
        setSubPacketHeader(new SignatureSubPacketHeader(30, false, numflags));
    }
    
    /** Returns true if the SUPPORTS_MDC flag has been set. */
    public boolean getModificationDetectionFlag() {
        return getFlag(0, SUPPORTS_MODIFICATION_DETECTION);
    }
    
    /** Set the NO_MODIFY flag.
     * @param set Toggle the flag on (true) or off (false).
     */
    public void setModificationDetectionFlag(boolean set) {
        setFlag(0, SUPPORTS_MODIFICATION_DETECTION, set);
    }
}
