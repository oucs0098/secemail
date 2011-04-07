package core.algorithmhandlers.openpgp.packets.v4signature;

import java.io.IOException;
import java.io.OutputStream;

import core.algorithmhandlers.openpgp.util.HashAlgorithmSettings;
import core.exceptions.AlgorithmException;

/** <p>A sub packet identifying a specific target signature that a signature 
 * refers to.</p>
 */
public class SignatureTargetSubPacket extends SignatureSubPacket {
	
	/** The public key algorithm */
	private int publicKeyAlgorithm;
	
	/** The hash algorithm */
	private int hashAlgorithm;
	
	/** The digest, langth depends on the has algorithm used */
	private byte[] hash;

	/** Creates a new instance of SignatureTargetSubPacket */
	public SignatureTargetSubPacket() {
	}

	/** Creates a new instance of SignatureTargetSubPacket
	 * @param publicKeyAlgorithm The public key algorithm used to encrypt the digest
	 * @param hashAlgorithm The hash algorithm used
	 * @param hash The digest itself
	 */
	public SignatureTargetSubPacket(int publicKeyAlgorithm, int hashAlgorithm, byte[] hash) {
		this.publicKeyAlgorithm = publicKeyAlgorithm;
		this.hashAlgorithm = hashAlgorithm;
		this.hash = hash;
	}

	/** @see core.algorithmhandlers.openpgp.packets.v4signature.SignatureSubPacket#decode(
	 * byte[]) 
	 */
	public void decode(byte[] data) throws IOException {
		publicKeyAlgorithm = (data[0] & 0xff);
		hashAlgorithm = (data[1] & 0xff);
		
		int digestSize;
		try {
			digestSize = HashAlgorithmSettings.getDigestSize(hashAlgorithm);
			if (data.length != (digestSize+2))
				throw new AlgorithmException("Incorrect digest length in " +
						"SignatureTargetSubPacket");
		} catch(AlgorithmException e) {throw new IOException(e.getMessage());}
		
		hash = new byte[digestSize];
		System.arraycopy(data, 2, hash, 0, digestSize);
	}

	/** @see core.algorithmhandlers.openpgp.packets.v4signature.SignatureSubPacket#encode(
	 * java.io.OutputStream) 
	 */
	public void encode(OutputStream out) throws IOException {
		out.write(publicKeyAlgorithm);
		out.write(hashAlgorithm);
		out.write(hash);
	}
}