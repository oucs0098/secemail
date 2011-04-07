package core.algorithmhandlers.openpgp.packets;

import core.algorithmhandlers.openpgp.util.SessionKey;
import core.exceptions.AlgorithmException;

/** A convenient way to deal with the multiple symmetrically encrypted data 
 * packets. This packet is not in the spec, but it helps to be able to treat
 * the SymmetricallyEncryptedDataPacket and the 
 * SymmetricallyEncryptedIntegrityProtectedDataPacket the same way.
 */
public abstract class EncryptedDataPacket extends ContainerPacket {

	/** <p>Decrypt the raw encoded data.</p>
     * <p>This method will attempt to decode the raw data and populate the internal
     * array of packets that can be read using the unpack method.</p>
     * <p>You should call this method on the packet after reading it in from a 
     * stream in order to get access to its sub packets.</p>
     * @throws AlgorithmException if something went wrong, most likely that the 
     * wrong session key was used.
     */
	public abstract void decryptAndDecode(SessionKey sessionkey) 
			throws AlgorithmException;
	
	/** <p>Encrypt the packet contents.</p>
     * <p>This method serialises and encrypts all the packet contents and stores
     * it in rawData.</p>
     * <p>You MUST call this method before writing the packet to the stream, 
     * otherwise the packet will not be written correctly (if at all).</p>
     * @param sessionkey The session key and algorithm to use.
     * @throws AlgorithmException if something went wrong.
     */
	public abstract void encryptAndEncode(SessionKey sessionkey) 
			throws AlgorithmException;

}
