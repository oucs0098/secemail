/*
 * Oxford Brookes University Secure Email Proxy 
 * Copyright (C) 2002/3 Oxford Brookes University Secure Email Project
 * http://secemail.brookes.ac.uk
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 * 
 * The Secure Email Project is:
 * 
 * Marcus Povey <mpovey@brookes.ac.uk> or <icewing@dushka.co.uk>
 * Damian Branigan <dbranigan@brookes.ac.uk>
 * George Davson <gdavson@brookes.ac.uk>
 * David Duce <daduce@brookes.ac.uk>
 * Simon Hogg <simon.hogg@brookes.ac.uk>
 * Faye Mitchell <frmitchell@brookes.ac.uk>
 * 
 * For further information visit the secure email project website.
 */

package core.algorithmhandlers.openpgp.packets;
import core.algorithmhandlers.keymaterial.*;
import core.algorithmhandlers.openpgp.util.*;
import core.exceptions.AlgorithmException;
import core.exceptions.ChecksumFailureException;
import org.bouncycastle.jce.provider.*;
import java.util.*;
import java.io.*;
import java.security.*;

import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * <p>A class representing a v3 or v4 secret key packet.</p>
 * <p>This has the same format as a public key packet, but also contains the secret key info at the end.</p>
 */
public class SecretKeyPacket extends KeyPacket {
    
    /** Define the S2K usage convention used. */
    private int s2kUsageConvention;
    
    /** Symmetric Encryption Algorithm used to encrypt the data. */
    private int symmetricAlgorithm;
    
    /** A s2k specifier, as defined by the usage convention */
    private S2K s2kSpecifier;
    
    /** If message was encrypted, a initial vector. */
    private byte IV[];
    
    /** Encrypted private key data (inc checksum) */
    private byte encryptedKeyData[];

    
    /** Creates a new instance of SecretKeyPacket. Does not create a header.*/
    public SecretKeyPacket() {
    }
    
    /** Create a version 3 packet. 
     * @param expiry Number of days this key is valid for, 0 for no expiry.
     * @param keyAlgorithm What public key algorithm is being used.
     * @param symmetricAlg The Symmetric algorithm to use to encrypt the key material.
     * @param s2kSpec The S2K Specifier as defined by the usage convention.
     * @param passPhrase The passphrase to encrypt the key data with.
     * @param keyParams The raw unencrypted key data (public & private) as series of MPIs. 
     * @deprecated Use of this constructor can lead to incorrect key IDs being generated when key material is saved in public and secret key rings. 
     * @throws AlgorithmException if the packet could not be created.
     */
    public SecretKeyPacket(int expiry, int keyAlgorithm,  int symmetricAlg, S2K s2kSpec, byte passPhrase[], AsymmetricAlgorithmParameters keyParams) throws AlgorithmException {
        super(expiry, keyAlgorithm, keyParams);
        setS2KUsageConvention(255); // always generate this
        setSymmetricAlgorithm(symmetricAlg);
        setS2KSpecifier(s2kSpec);
        encryptKeyData(passPhrase);
        
        int bsize = keyParams.encodePublicKeyComponents().length + 8;
        
        // usage convention
        bsize++;
        
        if (getS2KUsageConvention()!=0) {
            if (getS2KUsageConvention()==255 || getS2KUsageConvention()==254) {
                // symmetric algorithn
                bsize++;
                
                // s2k specifier
                bsize+= getS2KSpecifier().toByteArray().length;
            }
            
            // IV
            bsize+=IV.length;
        }
        
        // data + checksum
        bsize+=encryptedKeyData.length;
        
        setPacketHeader(new PacketHeader(5, false, bsize));
    }
    
    /** Create a version 4 packet. 
     * @param keyAlgorithm What public key algorithm is being used.
     * @param symmetricAlg The Symmetric algorithm to use to encrypt the key material.
     * @param s2kSpec The S2K Specifier as defined by the usage convention.
     * @param passPhrase The passphrase to encrypt the key data with.
     * @param keyParams The raw unencrypted key data (public and private) as series of MPIs.
     * @deprecated Use of this constructor can lead to incorrect key IDs being generated when key material is saved in public and secret key rings. 
     * @throws AlgorithmException if the packet could not be created.
     */
    public SecretKeyPacket(int keyAlgorithm, int symmetricAlg, S2K s2kSpec, byte passPhrase[], AsymmetricAlgorithmParameters keyParams) throws AlgorithmException {
        super(keyAlgorithm, keyParams);
        setS2KUsageConvention(255); // always generate this
        setSymmetricAlgorithm(symmetricAlg);
        setS2KSpecifier(s2kSpec);
        encryptKeyData(passPhrase);
        
        int bsize = keyParams.encodePublicKeyComponents().length + 6;
        
        // usage convention
        bsize++;
        
        if (getS2KUsageConvention()!=0) {
            if (getS2KUsageConvention()==255 || getS2KUsageConvention()==254) {
                // symmetric algorithn
                bsize++;
                
                // s2k specifier
                bsize+= getS2KSpecifier().toByteArray().length;
            }
            
            // IV
            bsize+=IV.length;
        }
        
        // data + checksum
        bsize+=encryptedKeyData.length;
        
        setPacketHeader(new PacketHeader(5, false, bsize));
    }
    
    /** Create a version 3 packet. 
     * @param creationdate A date object representing the time the packet is created. If you are creating a PGP keyring you should use the same Date object for both the public and secret key packets. This will ensure that both halfs of the keypair have the same key ID.
     * @param expiry Number of days this key is valid for, 0 for no expiry.
     * @param keyAlgorithm What public key algorithm is being used.
     * @param symmetricAlg The Symmetric algorithm to use to encrypt the key material.
     * @param s2kSpec The S2K Specifier as defined by the usage convention.
     * @param passPhrase The passphrase to encrypt the key data with.
     * @param keyParams The raw unencrypted key data (public & private) as series of MPIs.
     * @throws AlgorithmException if the packet could not be created.
     */
    public SecretKeyPacket(Date creationdate, int expiry, int keyAlgorithm, int symmetricAlg, S2K s2kSpec, byte passPhrase[], AsymmetricAlgorithmParameters keyParams) throws AlgorithmException {
        super(creationdate, expiry, keyAlgorithm, keyParams);
        setS2KUsageConvention(255); // always generate this
        setSymmetricAlgorithm(symmetricAlg);
        setS2KSpecifier(s2kSpec);
        encryptKeyData(passPhrase);
        
        int bsize = keyParams.encodePublicKeyComponents().length + 8;
        
        // usage convention
        bsize++;
        
        if (getS2KUsageConvention()!=0) {
            if (getS2KUsageConvention()==255 || getS2KUsageConvention()==254) {
                // symmetric algorithn
                bsize++;
                
                // s2k specifier
                bsize+= getS2KSpecifier().toByteArray().length;
            }
            
            // IV
            bsize+=IV.length;
        }
        
        // data + checksum
        bsize+=encryptedKeyData.length;
        
        setPacketHeader(new PacketHeader(5, false, bsize));
    }
    
    /** Create a version 4 packet. 
     * @param creationdate A date object representing the time the packet is created. If you are creating a PGP keyring you should use the same Date object for both the public and secret key packets. This will ensure that both halfs of the keypair have the same key ID.
     * @param keyAlgorithm What public key algorithm is being used.
     * @param symmetricAlg The Symmetric algorithm to use to encrypt the key material.
     * @param s2kSpec The S2K Specifier as defined by the usage convention.
     * @param passPhrase The passphrase to encrypt the key data with.
     * @param keyParams The raw unencrypted key data (public and private) as series of MPIs.
     * @throws AlgorithmException if the packet could not be created.
     */
    public SecretKeyPacket(Date creationdate, int keyAlgorithm, int symmetricAlg, S2K s2kSpec, byte passPhrase[], AsymmetricAlgorithmParameters keyParams) throws AlgorithmException {
        super(creationdate, keyAlgorithm, keyParams);
        setS2KUsageConvention(255); // always generate this
        setSymmetricAlgorithm(symmetricAlg);
        setS2KSpecifier(s2kSpec);
        encryptKeyData(passPhrase);
        
        int bsize = keyParams.encodePublicKeyComponents().length + 6;
        // usage convention
        bsize++;
        
        if (getS2KUsageConvention()!=0) {
            if (getS2KUsageConvention()==255 || getS2KUsageConvention()==254) {
                // symmetric algorithn
                bsize++;
                // s2k specifier
                bsize+= getS2KSpecifier().toByteArray().length;
            }
            // IV
            bsize+=IV.length;
        }
        // data + checksum
        bsize+=encryptedKeyData.length;
        setPacketHeader(new PacketHeader(5, false, bsize));
    }
    
    /** Set the s2k usage convention. */
    protected void setS2KUsageConvention(int s2k) {
        s2kUsageConvention = s2k;
    }
    
    /** Get the s2k usage convention. 
     * @return the s2k usage convention in use, 0 = not encrypted, 255 [or 254] = s2k specifier is given, any other value is a symmetric encryption algorithm specifier.
     */
    public int getS2KUsageConvention() {
        return s2kUsageConvention;
    }
    
    /** Set the symmetric algorithm.*/
    protected void setSymmetricAlgorithm(int algorithm) {
        symmetricAlgorithm = algorithm;
    }
    
    /** Get the symmetric algorithm specified.
     * @return the symmetric algorithm used.
     */
    public int getSymmetricAlgorithm() {
        if (getS2KUsageConvention()==255 || getS2KUsageConvention()==254)
            return symmetricAlgorithm;
        else
            return getS2KUsageConvention();
    }
    
    /** Set the s2k specifier. */
    protected void setS2KSpecifier(S2K spec) {
        s2kSpecifier = spec;
    }
    
    /** Get the s2k specifier. 
     * @return the s2k specifier if s2k usage was 255 [or 254]. Return value is not defined if the s2k usage convention is not 255 [or 254].
     */
    public S2K getS2KSpecifier() {
        return s2kSpecifier;
    }
     
    /** 
     * <p>Sets the secret key data.</p>
     * <p>The public data is stored in the usual way, the secret data is encrypted and stored in its encrypted form.</p>
     * <p>You must have previously set the key data using setKeyData() before calling this method (unless you have loaded this key from a file in
     * which case you should call decryptKeyData() before hand).</p>
     * @param keyParams a AsymmetricAlgorithmParameters object holding the public and secret parameters for the given algorithm.
     * @throws AlgorithmException if something went wrong.
     */
    protected void encryptKeyData(byte passPhrase[]) throws AlgorithmException {
        
        try {
            // processor output buffer
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            // get the raw data to start with
            byte cleartext[] = getKeyData().encodePrivateKeyComponents();   
            int checksumval = Hash.calculatePGPHash(cleartext);
                        
            // construct raw data
            out.write(cleartext);
            out.write((checksumval >> 8) &0xff);
            out.write(checksumval &0xff);
            
            // process raw data
            if (getS2KUsageConvention()==0) { // not encrypted
                encryptedKeyData = out.toByteArray();
            } else { // data must be encrypted
                // Test to see if a S2K specifier was given, if not then use MD5
//                if (getS2KUsageConvention()<254) { 
//                    setS2KSpecifier(new S2K(1)); // MD5
//                }
                
                // Generate key
                SecretKey key = getS2KSpecifier().generateKey(passPhrase, getSymmetricAlgorithm());

                // Create cipher
                Cipher cipher = Cipher.getInstance(SymmetricAlgorithmSettings.getCipherText(getSymmetricAlgorithm()) 
                                                        + "/PGPCFB/" // use standard CFB mode for this case
                                                        + SymmetricAlgorithmSettings.getPaddingText(getSymmetricAlgorithm())
                                                        ,"BC");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                
                if (getVersion()==3) { // version 3 packet encryption
                    //throw new AlgorithmException("Version 3 Secret key packets are currently not supported!");
                    
                    ByteArrayInputStream tmpIn = new ByteArrayInputStream(cleartext);
                    ByteArrayOutputStream tmpOut = new ByteArrayOutputStream();
                    
                    while (tmpIn.available()>0) {
                        int size = (((tmpIn.read() & 0xFF ) << 8) | (tmpIn.read() & 0xFF));
                        
                        byte [] mpidat = new byte[(size + 7) / 8];
                        tmpIn.read(mpidat);      

                        tmpOut.write(MPI.toByteArray(cipher.update(mpidat)));
                        //BigInteger big = MPI.valueOf(tmpIn);
                        
                        //tmpOut.write(MPI.toByteArray(cipher.update(big.toByteArray())));
                    }
                    
                    // write checksum
                    tmpOut.write((checksumval >> 8) & 0xff);
                    tmpOut.write(checksumval & 0xff);
                    
                    encryptedKeyData=tmpOut.toByteArray();
                    
                    
                } else { // version 4 packet encryption
                    // Encrypt data
                    encryptedKeyData = cipher.doFinal(out.toByteArray());
                }
                
                // Save the IV used
                IV = cipher.getIV();
            }
        } catch (Exception e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
    /**
     * <p>Returns the public and secret key data.</p>
     * @throws AlgorithmException if something went wrong.
     * @throws ChecksumFailureException if the decoded key data failed the checksum.
     */
    public void decryptKeyData(byte passPhrase[]) throws AlgorithmException, ChecksumFailureException {
        
        try {
            // checksum
            int checksum = 0;
            
            // hash codes
            byte[] decrypted_hash = null;
            byte[] recalculated_hash = null;

            // process data
            if (getS2KUsageConvention()==0) 
            { // not encrypted
               ByteArrayInputStream in = new ByteArrayInputStream(encryptedKeyData);
               getKeyData().decodePrivateKeyComponents(in);
               
               byte decchecksum[] = new byte[2];
               System.arraycopy(encryptedKeyData, encryptedKeyData.length-2, decchecksum, 0, 2);
               checksum = ((decchecksum[0] << 8) & 0xFF00) + (decchecksum[1] & 0x00FF);    
            } 
            else 
            { // data must be decrypted

                // Generate key
                SecretKey key = getS2KSpecifier().generateKey(passPhrase, getSymmetricAlgorithm());

                // Create cipher
                IvParameterSpec iv = new IvParameterSpec(IV); 
                Cipher cipher = Cipher.getInstance(SymmetricAlgorithmSettings.getCipherText(getSymmetricAlgorithm()) 
                                                        + "/PGPCFB/" // use standard CFB mode for this case
                                                        + SymmetricAlgorithmSettings.getPaddingText(getSymmetricAlgorithm())
                                                        ,"BC");
                cipher.init(Cipher.DECRYPT_MODE, key, iv);
                
                if (getVersion()==3) { // version 3 packet encryption
                    ByteArrayInputStream tmpIn = new ByteArrayInputStream(encryptedKeyData);
                    ByteArrayOutputStream tmpOut = new ByteArrayOutputStream();
                    
                    while (tmpIn.available()>2) {
                        
                        int size = (((tmpIn.read() & 0xFF ) << 8) | (tmpIn.read() & 0xFF));
                        
                        byte [] mpidat = new byte[(size + 7) / 8];
                        tmpIn.read(mpidat);      

                        tmpOut.write(MPI.toByteArray(cipher.update(mpidat)));
                    }
                    
                    // write checksum
                    checksum = ((tmpIn.read() << 8) & 0xFF00) + (tmpIn.read() & 0x00FF); 
                    
                    // read in decrypted MPI data
                    tmpIn = new ByteArrayInputStream(tmpOut.toByteArray());
                    getKeyData().decodePrivateKeyComponents(tmpIn);

                    //throw new AlgorithmException("Version 3 Secret key packets are currently not supported!");
                } 
                else 
                { // version 4 packet encryption
                	
                	// Decrypt data
					byte dectext[] = cipher.doFinal( encryptedKeyData );

                	if( getS2KUsageConvention() == 254 )
					{
                		decrypted_hash = new byte[20];
						byte deckm[] = new byte[dectext.length - 20];
						System.arraycopy( dectext, 0, deckm, 0, dectext.length - 20 );
						System.arraycopy( dectext, dectext.length - 20, decrypted_hash,
								0, 20 );
						
						// Construct key material and compute hash
						ByteArrayInputStream in = new ByteArrayInputStream( deckm );
						getKeyData().decodePrivateKeyComponents( in );
						
						MessageDigest sha = MessageDigest.getInstance("SHA-1");
						sha.update( deckm );
						recalculated_hash = sha.digest();
					}
					else
					{
						byte decchecksum[] = new byte[2];
						byte deckm[] = new byte[dectext.length - 2];
						System.arraycopy( dectext, 0, deckm, 0, dectext.length - 2 );
						System.arraycopy( dectext, dectext.length - 2, decchecksum,
								0, 2 );
						
						// Construct key material and checksum
						ByteArrayInputStream in = new ByteArrayInputStream( deckm );
						getKeyData().decodePrivateKeyComponents( in );

						checksum = ( ( decchecksum[0] << 8 ) & 0xFF00 )
								+ ( decchecksum[1] & 0x00FF );
					} 
                }
            }

            // compare checksums or hashes
            if( getS2KUsageConvention() == 254 )
            {
            	if( decrypted_hash != null && recalculated_hash != null && Arrays.equals( decrypted_hash, recalculated_hash ) )
            	{
            		System.out.println( "hashes match" );
            	}
            	else
            	{ //TODO: should differentiate this from the checksum exception really
            		throw new ChecksumFailureException("Hash does not match, you probably entered the wrong pass phrase.");
            	}
            }
            else
            {
            	if (checksum != Hash.calculatePGPHash(getKeyData().encodePrivateKeyComponents())) 
                {
                    throw new ChecksumFailureException("Checksum does not match, you probably entered the wrong pass phrase.");  // TODO: Throw separate exception to catch passphrase problems?
                }
                else
                {
                	System.out.println( "checksums match" );
                }
            }
            
        } catch (ChecksumFailureException c) {
            throw c;
        } catch (Exception e) {
        	e.printStackTrace();
            throw new AlgorithmException(e.getMessage());
        }
    }
    
    /**
     * <p>A method constructs a packet out of raw binary data.</p>
     * <p>You should implement this in all your packets. If a packet is a container packet
     * you must also populate the subpackets vector by extracting and constructing the relevent packets.</p>
     * @param data[] The packet body data as a raw binary bytestream. If you are using OpenPGPPacketInputStream the header will automatically be created for you.
     * @throws AlgorithmException if there was a problem.
     */
    public void buildPacket(byte[] data) throws AlgorithmException {
        try {
            ByteArrayInputStream in = new ByteArrayInputStream(data);
            super.buildKeyPacketFromStream(in);
            
            setS2KUsageConvention(in.read());  // read usage convention
            if (getS2KUsageConvention()!=0) { // only do this if the key is encrypted
                if (getS2KUsageConvention()==255 || getS2KUsageConvention()==254) {
                    setSymmetricAlgorithm(in.read());  // Symmetric algorithm
                    s2kSpecifier = new S2K(in);  // s2k specifier
                } else {
                	// spec (section 3.7.2.1) states that any other value is a 
                	// symmetric key encryption algorithm identifier, and uses 
                	// simple s2k with md5
                	symmetricAlgorithm = getS2KUsageConvention();
                	s2kSpecifier = new S2K(HashAlgorithmSettings.MD5);
                }
                // Read IV
                IV = new byte[SymmetricAlgorithmSettings.getDefaultBlockSize( symmetricAlgorithm ) / 8];
                in.read(IV);
            }
            // Read secret key data and checksum
            encryptedKeyData = new byte[in.available()];
            in.read(encryptedKeyData);
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
  
    }
    
    /**
     * <p>A method that produces a straight binary representation of this packet.</p>
     * <p>You should override this as necessary.</p>
     * <p>You should also encode the header as part of this method by calling the header object's
     * encodeHeader method.</p>
     * @throws AlgorithmException if there was a problem.
     */
    public byte[] encodePacket() throws AlgorithmException {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            // encode public key portion
            out.write(getPacketHeader().encodeHeader());
            // write body
            out.write(encodePacketBody());
            return out.toByteArray();
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
    /**
     * <p>A method that produces a straight binary representation of this packet's BODY.</p>
     * <p>You should override this as necessary.</p>
     * @throws AlgorithmException if there was a problem.
     */
    public byte[] encodePacketBody() throws AlgorithmException {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            // encode public key portion
            out.write(super.encodePacketBody());
            // write usage convention
            out.write(getS2KUsageConvention() & 0xff);
            
            if (getS2KUsageConvention()!=0) { // only do this if the key is encrypted
                if (getS2KUsageConvention()==255 || getS2KUsageConvention()==254) {
                    // OPTIONAL: Symmetric algorithm
                    out.write(getSymmetricAlgorithm() & 0xff);
                    // OPTIONAL: s2k specifier
                    out.write(getS2KSpecifier().toByteArray());
                }
                // OPTIONAL: write IV (if was encrypted)
                out.write(IV);
            }
            // write encrypted secret key portion & checksum
            out.write(encryptedKeyData);
            return out.toByteArray();
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
}
