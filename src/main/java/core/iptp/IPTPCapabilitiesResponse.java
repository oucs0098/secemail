package core.iptp;

/**
 * <p>Was the capabilities command accepted.</p>
 * <p>These scan listings are currently relayed with no further analysis.</p>
 */
public class IPTPCapabilitiesResponse extends IPTPCommandResponse {
	
	/** The scan listing. */
    private String scanListing;
    
    /** Creates a single line response to the message */
    public IPTPCapabilitiesResponse(boolean isok) {
        setOk(isok);
        setScanListing("");
    }

    /** Creates a new instance of IPTPListResponse containing a scan listing
     * @param isok Was the command successful or not
     * @param scanlst The email scan listing
     */
    public IPTPCapabilitiesResponse(boolean isok, String scanlst) {
        setOk(isok);
        setScanListing(scanlst);
    }

    /** Set the capabilities list. */
    protected void setScanListing(String scanlst) {
        scanListing = new String(scanlst);
    }

    /** Get the capabilities list. Should be set to a multiline response.*/
    public String getScanListing() {
        return scanListing;
    }
}
