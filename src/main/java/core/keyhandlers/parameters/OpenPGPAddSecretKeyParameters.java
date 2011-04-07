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
import core.exceptions.KeyHandlerException;
import java.util.Date;

/**
 * Key parameters for adding secret keys to a secret key store.
 */
public class OpenPGPAddSecretKeyParameters extends OpenPGPAddKeyParameters {
    
    private byte [] passPhrase;
    
    private int symmetricAlgorithm;
    
    private int hashAlgorithm;
    
    /** Creates a new instance of OpenPGPAddSecretKeyParameter.     
     * @param creationDate the creation date that will be set in the key packet.
     * @param keyAlgorithm The public key algorithm of the key.
     * @param symmetricPrefs An ordered list denoting symmetric encryption algorithm preferences (only used on primary keys).
     * @param passphrase The passphrase to use to encrypt the key material with.
     * @param symmetricAlg The symmetric algorithm to use to encrypt the secret key material with
     * @param hashAlg The hash algorithm to use with the S2K specifier.
     */
    public OpenPGPAddSecretKeyParameters(Date creationDate, int keyAlgorithm,
			int signingKeyAlgorithm, byte[] symmetricPrefs, byte[] hashPrefs,
			byte[] compressionPrefs, byte[] passphrase, int symmetricAlg,
			int hashAlg) throws KeyHandlerException {
        super(creationDate, keyAlgorithm, signingKeyAlgorithm, symmetricPrefs, 
        		hashPrefs, compressionPrefs);
        
        if (passphrase == null)
            throw new KeyHandlerException("null passphrase is not permitted!");
       
        passPhrase = passphrase;
        symmetricAlgorithm = symmetricAlg;
        hashAlgorithm = hashAlg;
    }
    
    /**
     * <p>Return the passphrase used to encrypt the secret key material.</p>
     */
    public byte[] getPassPhrase() {
        return passPhrase;
    }
    
    /** 
     * <p>Return the symmetric algorithm used to encrypt the key material.</p>
     */
    public int getSymmetricAlgorithm() {
        return symmetricAlgorithm;
    }
    
    /** 
     * <p>Return the hash algorithm used to convert the passphrase to a key.</p>
     */
    public int getHashAlgorithm() {
        return hashAlgorithm;
    }

}
