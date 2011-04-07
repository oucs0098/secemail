package core.algorithmhandlers.openpgp.packets.v4signature;

import java.io.IOException;
import java.io.OutputStream;
import core.algorithmhandlers.openpgp.packets.SignaturePacket;
import core.exceptions.AlgorithmException;

/** <p>A sub packet containing a complete signature packet body.</p> */
public class EmbeddedSignatureSubPacket extends SignatureSubPacket {

	/** The embedded signature - this should not include the header */
	private SignaturePacket embeddedSignature;
	
	/** Create a new instance of EmbeddedSignatureSubPacket */
	public EmbeddedSignatureSubPacket() {
		super();
	}

	/** Create a new instance of EmbeddedSignatureSubPacket
	 * @param embeddedSignature The signature to embed in the sub packet
	 */
	public EmbeddedSignatureSubPacket(SignaturePacket embeddedSignature) {
		super();
		this.embeddedSignature = embeddedSignature;
	}

	/** @see core.algorithmhandlers.openpgp.packets.v4signature.SignatureSubPacket#decode(
	 * byte[]) 
	 */
	public void decode(byte[] data) throws IOException {
		this.embeddedSignature = new SignaturePacket();
		// a complete signature packet body
		try {
			this.embeddedSignature.buildPacket(data);
		} catch(AlgorithmException e) {
			throw new IOException(e.getMessage());
		}
	}

	/** @see core.algorithmhandlers.openpgp.packets.v4signature.SignatureSubPacket#encode(
	 * java.io.OutputStream) 
	 */
	public void encode(OutputStream out) throws IOException {
		getSubPacketHeader().encode(out);
		try {
			out.write(getEmbeddedSignature().encodePacketBody());
		} catch(AlgorithmException e) {
			throw new IOException(e.getMessage());
		}
	}

	/** Gets the embedded signature
	 * @return the embedded signature
	 */
	public SignaturePacket getEmbeddedSignature() {
		return embeddedSignature;
	}

	/** Sets the embedded signature
	 * @param embeddedSignature the signature packet to embed
	 */
	public void setEmbeddedSignature(SignaturePacket embeddedSignature) {
		this.embeddedSignature = embeddedSignature;
	}
}
