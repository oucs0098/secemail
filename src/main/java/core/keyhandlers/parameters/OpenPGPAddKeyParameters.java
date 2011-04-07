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

package core.keyhandlers.parameters;
import core.keyhandlers.KeyHandlerParameters;
import java.util.Date;

/**
 * <p>A class holding the information necessary to add an OpenPGP key to a key
 * store.</p>
 */
public class OpenPGPAddKeyParameters implements KeyHandlerParameters {
    
    /** Public key algorithm of the key being added.*/
    private int publicKeyAlgorithm;
    
    /** Public key algorithm of the signing key.*/
    private int signingKeyAlgorithm;
    
    /** A list of symmetric algorithm preferences. */
    private byte[] symmetricAlgorithmPrefs;
    
    /** A list of hash algorithm preferences. */
    private byte[] hashAlgorithmPrefs;
    
    /** A list of compression algorithm preferences. */
    private byte[] compressionAlgorithmPrefs;
    
    /** The date to stamp the packet as created. */
    private Date creationDate;
    
    /**
	 * Creates a new instance of OpenPGPAddKeyParameters.
	 * 
	 * @param creationDate
	 *            the creation date that will be set in the key packet.
	 * @param keyAlgorithm
	 *            The public key algorithm of the key.
	 * @param symmetricPrefs
	 *            An ordered list denoting symmetric encryption algorithm
	 *            preferences (only used on primary keys).
	 * @param signingKeyAlgorithm
	 *            The public key algorithm of the signing key (not necessarily
	 *            the same as the public key algorithm)
	 */
    public OpenPGPAddKeyParameters(Date creationDate, int keyAlgorithm,
			int signingKeyAlgorithm, byte[] symmetricPrefs, byte[] hashPrefs,
			byte[] compressionPrefs) {
		setCreationDate(creationDate);
		setPublicKeyAlgorithm(keyAlgorithm);
		setSigningKeyAlgorithm(signingKeyAlgorithm);
		setSymmetricAlgorithmPrefs(symmetricPrefs);
		setHashAlgorithmPrefs(hashPrefs);
		setCompressionAlgorithmPrefs(compressionPrefs);
	}
    
    /**
	 * <p>
	 * Return the PGP Public key algorithm being used.
	 * </p>
	 * <p>
	 * Returns the PGP code for the public key algorithm being used.
	 * </p>
	 */
    public int getPublicKeyAlgorithm() {
        return publicKeyAlgorithm;
    }
    
    /** Set the public key algorithm being used. */
    protected void setPublicKeyAlgorithm(int alg) {
        publicKeyAlgorithm = alg;
    }
    
    /** @return an ordered list of symmetric algorithm preferences. */
    public byte[] getSymmetricAlgorithmPrefs() {
        return symmetricAlgorithmPrefs;
    }
    
    /** Set the symmetric algorithm being used. */
    protected void setSymmetricAlgorithmPrefs(byte prefs[]) {
        symmetricAlgorithmPrefs = prefs;
    }
    
    /** Get the creation date timestamp. */
    public Date getCreationDate() {
        return creationDate;
    }
    
    /** Set the creation date timestamp. */
    protected void setCreationDate(Date date) {
        creationDate = date;
    }

	/** @return the signing key algorithm */
	public int getSigningKeyAlgorithm() {
		return signingKeyAlgorithm;
	}

	/** @param signingKeyAlgorithm the signing key algorithm to set */
	protected void setSigningKeyAlgorithm(int signingKeyAlgorithm) {
		this.signingKeyAlgorithm = signingKeyAlgorithm;
	}

	/** @return the compression algorithm preferences  */
	public byte[] getCompressionAlgorithmPrefs() {
		return compressionAlgorithmPrefs;
	}

	/** @param compressionAlgorithmPrefs compression algorithm preferences */
	protected void setCompressionAlgorithmPrefs(byte[] compressionPrefs) {
		this.compressionAlgorithmPrefs = compressionPrefs;
	}

	/** @return the hash algorithm preferences */
	public byte[] getHashAlgorithmPrefs() {
		return hashAlgorithmPrefs;
	}

	/** @param hashAlgorithmPrefs the hashAlgorithmPrefs to set */
	protected void setHashAlgorithmPrefs(byte[] hashAlgorithmPrefs) {
		this.hashAlgorithmPrefs = hashAlgorithmPrefs;
	}
}
