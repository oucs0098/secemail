package core.iptp;

/**
 * <p>Request details about a server's capabilities.</p>
 * <p>Expects a multiline response if the command was successful.</p>
 */
public class IPTPCapabilities extends IPTPCommand {
	
    /** <p>Creates a new instance of IPTPCapabilities (equiv to "capa" in extended 
     * POP3).</p> 
     */
    public IPTPCapabilities() {
        setExpectingMultilineResponse(true);
    }
}
