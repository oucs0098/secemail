package openpgp.keystore.model;

import java.io.IOException;

import core.algorithmhandlers.openpgp.OpenPGPPacketOutputStream;
import core.exceptions.AlgorithmException;

/** <p>For implementation by classes that wrap public keyring packets</p>
 * @version $Id: ExportableKeyringPacketWrapper.java,v 1.1 2007-08-07 13:15:57 nigelb Exp $
 */
public interface ExportableKeyringPacketWrapper extends Trustable {
	
	/** <p>Method to allow the public keyring packet that is wrapped within the 
	 * implementing class to be exported to a given packet output stream.</p>
	 * @param out output stream to which the wrapped object should be written
	 * @param includeTrust Whether to include the trust packet in the output
	 */
	public void writePublicKeyringPacket(OpenPGPPacketOutputStream out,
			boolean includeTrust) throws IOException, AlgorithmException;
	
	/** <p>Method to allow the private keyring packet that is wrapped within the 
	 * implementing class to be exported to a given packet output stream.</p>
	 * @param out output stream to which the wrapped object should be written
	 * @param includeTrust Whether to include the trust packet in the output
	 */
	public void writePrivateKeyringPacket(OpenPGPPacketOutputStream out,
			boolean includeTrust) throws IOException, AlgorithmException;
	
}
