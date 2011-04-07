package core.keyhandlers.identifiers;

import core.exceptions.KeyHandlerException;
import core.keyhandlers.KeyIdentifier;

/** Method to encapsulate a free-text search string, for use in keyserver
 * searches.
 * @version $Id: OpenPGPFreeTextKeyIdentifier.java,v 1.2 2007-07-07 21:24:23 nigelb Exp $
 */
public class OpenPGPFreeTextKeyIdentifier implements KeyIdentifier {

	/** Search String */
    private String text;
    
    /** Creates a new instance of OpenPGPTextKeyIdentifier.
     * @param id[] the 8 byte key ID being looked for.
     * @throws KeyHandlerException if the key id provided is the wrong length.
     */
    public OpenPGPFreeTextKeyIdentifier(String text) {
    	super();
        this.text = text;
    }
    
	/** @see core.keyhandlers.KeyIdentifier#getDefaultID()
	 */
	public byte[] getDefaultID() throws KeyHandlerException {
		return text.getBytes();
	}

}
