package core.algorithmhandlers.openpgp.packets;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import core.algorithmhandlers.openpgp.util.SessionKey;
import core.algorithmhandlers.openpgp.util.SymmetricAlgorithmSettings;
import core.exceptions.AlgorithmException;

/** <p>A symmetrically encrypted container, with new added authentication.</p>
 * <p>This packet contains other pgp packets and encrypts them. This packet provides
 * the main body of a pgp message.</p>
 * <p>The class is given a session key which can be obtained from a previous public or
 * symmetrically encrypted session key packet, or the MD5 hash of a passphrase.</p>
 * <p>Note: This container DOES NOT automatically unpack sub packets into a readable 
 * form for security reasons. 
 * You must encode and decode contained packets EXPLICITLY using the appropriate 
 * decrypt / encrypt methods and provide the appropriate session keys.</p>
 * <p><b>IMPORTANT NOTE:</b> As with the CompressedDataPacket, unless this packet is
 * loaded from a stream _and_ no calls to add() have been made, the PacketHeader's 
 * length type and bodylength tags are MEANINGLESS! It is not possible to accurately
 * calculate the size of the body before it is encoded. Therefore this class'
 * encodePacket() method recalculates the header length information. 
 */
public class SymmetricallyEncryptedIntegrityProtectedDataPacket extends
		EncryptedDataPacket {

	/** The version number. The only currently defined value is 1. */
	private int version;
	
	/** The encrypted encoded form of the packet populated by buildPacket. Also 
	 * contains OpenPGPs weird IValike thingy. 
	 */
    private byte rawData[];
    
	/** Creates a new instance of SymmetricallyEncryptedIntegrityProtectedDataPacket. 
	 * Since this method is the same for both stream construction and manual 
	 * construction this method DOES generate a header, but with no size information 
	 * (see class documentation for the reason).
     */
    public SymmetricallyEncryptedIntegrityProtectedDataPacket() 
    		throws AlgorithmException {
        setPacketHeader(new PacketHeader(18, false));
        setVersion(1);
    }
    
    /** Set the version type of this packet. Currently only version 1 is defined.*/
    protected void setVersion(int packetversion) {
        version = packetversion;
    }
    
    /** Get the version type of the key.*/
    public int getVersion() {
        return version;
    }
    
    /**
	 * @see core.algorithmhandlers.openpgp.packets.EncryptedDataPacket#decryptAndDecode(
	 * SessionKey)
	 */
    public void decryptAndDecode(SessionKey sessionkey) throws AlgorithmException {
        
        try {
        	// the algorithm id
        	int algorithm = sessionkey.getAlgorithm();
        	
        	// the blocksize
            int blockSize = SymmetricAlgorithmSettings.getDefaultBlockSize(algorithm)/8;
            
            // the prefix size
            int prefixSize = blockSize + 2;
            
            // the message digest class - if the version changes to allow different 
            // digests, this is where to add the feature
            MessageDigest md = MessageDigest.getInstance("SHA1");
            
            // convert session key to keyspec
            SecretKey key = new SecretKeySpec(sessionkey.getSessionKey(), 
            		SymmetricAlgorithmSettings.getCipherText(algorithm));
            
            // create cipher (the way this packet is decoded is a strange case, and 
            // not like the regular symmetrically encrypted data packet)
            // requires the use of standard CFB mode
            String cipherText = SymmetricAlgorithmSettings.getCipherText(algorithm) + 
            		"/CFB/" + SymmetricAlgorithmSettings.getPaddingText(algorithm);
            Cipher cipher = Cipher.getInstance(cipherText,"BC");
            byte[]       iv = new byte[cipher.getBlockSize()];
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            
            debug.Debug.println(1, "cipher algorithm: " + cipher.getAlgorithm() );
            
            // get the raw decrypted packets
            byte[] decryptedData = cipher.doFinal(rawData);
            
            if (decryptedData[blockSize-2] != decryptedData[blockSize] || 
            		decryptedData[blockSize-1] != decryptedData[blockSize+1]) {
            	throw new AlgorithmException("IV mismatch: two byte check failure");
            }
            
            // sum of the data without initial IV-like bytes or the trailing MDC 
            // packet - for packet processing
            int verifiableDataLength = 
            	decryptedData.length - prefixSize - ModificationDetectionCodePacket.SIZE;
            byte[] verifiableData = new byte[verifiableDataLength];
            System.arraycopy(
            		decryptedData, prefixSize, verifiableData, 0, verifiableDataLength);
            
            // hashable data includes prefix data and MDC header 
            // (but not the digest itself)
            byte[] hashableData = new byte[decryptedData.length - md.getDigestLength()];
            System.arraycopy(decryptedData, 0, hashableData, 0, hashableData.length);
            
            // spec says that the hashing algorithm can only be only SHA-1
            byte[] digest = new byte[md.getDigestLength()];
            System.arraycopy(decryptedData, decryptedData.length - md.getDigestLength(), 
            		digest, 0, md.getDigestLength());
            debug.Debug.println(1, "Digest bytes: "); 
            debug.Debug.hexDump(1, digest);
            
            // Compute a SHA-1 hash of the verifiable data, compare it with the digest
            
            byte[] calculatedDigest = md.digest(hashableData);
            debug.Debug.println(1, "Recalculated digest bytes: ");
            debug.Debug.hexDump(1, calculatedDigest);
            
            // could use the 1.5 feature Arrays.deepEquals(), but earlier JDK 
            // compatibility would be nice
            for (int i = 0; i < md.getDigestLength(); ++i) {
            	if (calculatedDigest[i] != digest[i]) 
            		throw new AlgorithmException("Modification Detection Check Failed");
            }
            
            // decrypt and construct packets
            buildMultiplePackets(verifiableData);
            
        } catch (Exception e) {
        	e.printStackTrace();
            throw new AlgorithmException(e.getMessage());
        }
    }
    
    /**
	 * @see core.algorithmhandlers.openpgp.packets.EncryptedDataPacket#encryptAndEncode(
	 * SessionKey)
	 */
    public void encryptAndEncode(SessionKey sessionkey) throws AlgorithmException {

        try {
        	// the algorithm id
        	int algorithm = sessionkey.getAlgorithm();
        	
            // the blocksize
            int blockSize = SymmetricAlgorithmSettings.getDefaultBlockSize(algorithm)/8;
            
            // the message digest class - if the version changes to allow different 
            // digests, this is where to add the feature
            MessageDigest md = MessageDigest.getInstance("SHA1");
            
            // convert session key to keyspec
            SecretKey key = new SecretKeySpec(sessionkey.getSessionKey(), 
            		SymmetricAlgorithmSettings.getCipherText(algorithm));
            
            // create randomly generated IV-like prefix
            byte[] ivdata = new byte[blockSize+2];
            SecureRandom rnd = SecureRandom.getInstance("SHA1PRNG");
            rnd.nextBytes(ivdata);
            ivdata[blockSize] = ivdata[blockSize-2];
            ivdata[blockSize+1] = ivdata[blockSize-1];
            
            byte[] packetData = encodeMultiplePackets();
            
            byte[] hashableData = new byte[ivdata.length + packetData.length + 2];
            System.arraycopy(ivdata, 0, hashableData, 0, ivdata.length);
            System.arraycopy(packetData, 0, hashableData, ivdata.length, 
            		packetData.length);
            hashableData[hashableData.length-2] = (byte)0xD3 & (byte)0xFF;
            hashableData[hashableData.length-1] = (byte)0x14 & (byte)0xFF;
            
            // Compute a SHA-1 hash of the hashable data for the MDC packet
            byte[] digest = md.digest(hashableData);
            
            // add the digest to the data to be encrypted 
            byte[] dataToEncrypt = new byte[hashableData.length+md.getDigestLength()];
            System.arraycopy(hashableData, 0, dataToEncrypt, 0, hashableData.length);
            System.arraycopy(digest, 0, dataToEncrypt, hashableData.length, 
            		digest.length);
            
            // create the actual IV (blank)
            byte[] iv = new byte[blockSize];
            
            // create cipher
            String cipherText = SymmetricAlgorithmSettings.getCipherText(algorithm) +
            		"/CFB/" + SymmetricAlgorithmSettings.getPaddingText(algorithm);
            Cipher cipher = Cipher.getInstance(cipherText,"BC");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

            rawData = cipher.doFinal(dataToEncrypt);
    
        } catch (Exception e) {
            throw new AlgorithmException(e.getMessage());
        }
              
    }
    
	/**
	 * @see core.algorithmhandlers.openpgp.packets.Packet#buildPacket(byte[])
	 */
	public void buildPacket(byte[] data) throws AlgorithmException {
		try {
            ByteArrayInputStream in = new ByteArrayInputStream(data);

            // read version
            setVersion(in.read());
            
            rawData = new byte[data.length - 1];
            in.read(rawData); // store raw data in encoded + encrypted form
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
	}

	/**
	 * @see core.algorithmhandlers.openpgp.packets.Packet#encodePacket()
	 */
	public byte[] encodePacket() throws AlgorithmException {
		try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            // recalculate header length - extra packets could have been added
            setPacketHeader(new PacketHeader(18, true, encodePacketBody().length));
            
            // write the packet header
            out.write(getPacketHeader().encodeHeader());
            
            // write the packet body
            out.write(encodePacketBody());

            return out.toByteArray();
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
	}

	/**
	 * @see core.algorithmhandlers.openpgp.packets.Packet#encodePacketBody()
	 */
	public byte[] encodePacketBody() throws AlgorithmException {
		try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            // write the version
            out.write(getVersion() & 0xFF);
            
            // write the raw encrypted data
            out.write(rawData);

            return out.toByteArray();
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
	}
}
