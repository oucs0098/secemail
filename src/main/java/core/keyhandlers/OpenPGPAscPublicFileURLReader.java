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

package core.keyhandlers;
import core.algorithmhandlers.openpgp.*;
import core.algorithmhandlers.openpgp.packets.*;
import core.algorithmhandlers.openpgp.packets.v4signature.*;
import core.algorithmhandlers.openpgp.util.*;
import core.algorithmhandlers.keymaterial.*;
import core.keyhandlers.parameters.*;
import core.keyhandlers.identifiers.*;
import core.keyhandlers.keydata.*;
import core.exceptions.*;
import java.security.SecureRandom;
import java.security.PrivateKey;
import java.io.*;
import java.util.*;
import java.net.*;

/**
 * <p>Public keyring asc file format.</p>
 * <p>At the moment only read support (and as a result only the findKeys method) is implemented.</p>
 */
public class OpenPGPAscPublicFileURLReader extends OpenPGPAscPublicFile {
    
    /** Creates a new instance of OpenPGPAscPublicFileURLReader */
    public OpenPGPAscPublicFileURLReader() {
    }
    
    /** Creates a new instance of OpenPGPAscPublicFileURLReader */
    public OpenPGPAscPublicFileURLReader(String filename, KeyHandlerParameters parameters) {
        super(filename, parameters);
    }
    
    /**
     * <p>Add a number of keys to the key store.</p>
     * <p>This method is currently not implemented and will throw a KeyHandlerException if used.</p>
     * @param key[] The keys to store. If key[n] is an instance of OpenPGPKeyData then if possible the existing key packet is used. This enables you to import keys from other key sources.
     * @param idDetails[] Information identifying the keys. Should be of type OpenPGPStandardKeyIdentifier. Must be not null for primary (first) key.
     * @param parameters[] Any extra parameters needed, for example pass phrases for secret key stores etc, may be null.
     * @throws KeyHandlerException if something went wrong.
     */
    public void addKeys(KeyData[] key, KeyIdentifier[] idDetails, KeyHandlerParameters[] parameters) throws KeyHandlerException {
        throw new KeyHandlerException("Add keys is currently not supported.");
    }
    
    /**
     * <p>Delete a key matching the given id from a given key store.</p>
     * <p>This method is currently not implemented and will throw a KeyHandlerException if used.</p>
     * @param id A KeyIdentifier object specifying the key(s) to remove.
     * @param parameters Any extra parameters needed, for example pass phrases for secret key stores etc, may be null.
     * @return The number of keys removed.
     * @throws KeyHandlerException if something went wrong.
     */
    public int removeKeys(KeyIdentifier id, KeyHandlerParameters parameters) throws KeyHandlerException {
        throw new KeyHandlerException("Remove keys is currently not supported.");
    }
    
    /**
     * <p>Look for a key.</p>
     * <p>Looks for a key in the key store as specified by the key identifier.</p>
     * <p>The actual KeyIdentifier class used depends on the type of key being looked for.</p>
     * <p>If you specify a key with a specific key ID, then only that key will be returned. If you specify a key with a user name
     * then the primary key and all sub keys will be returned.</p>
     * <p>If you use a OpenPGPKeyIDKeyIdentifier to specify key you may use an 8 byte array of zeros to specify a wildcard. If this is the case, all keys in the keyring will be returned.</p>
     * @param id The key identifier that specifies the key being looked for.
     * @param parameters Any extra parameters needed, for example pass phrases for secret key stores etc, may be null.
     * @return An array of OpenPGPKeyData objects that contain (among other things) the key material and raw key packet, or NULL if no keys matching id could be found.
     * @throws ChecksumFailureException If the key data fails a checksum (usually because the wrong passphrase was supplied).
     * @throws KeyHandlerException if something went wrong.
     */ 
    public KeyObject[] findKeys(KeyIdentifier id, KeyHandlerParameters parameters) throws ChecksumFailureException, KeyHandlerException {
        try {
            URL url = new URL(getFileName());

            return findKeys(new DataInputStream(new BufferedInputStream(url.openStream())), id, parameters);
        } catch (ChecksumFailureException c) {
            throw c;
        } catch (KeyHandlerException k) {
            throw k;
        } catch (Exception e) {
            throw new KeyHandlerException(e.getMessage());
        }
    }
    
    /** Method to return a readable description of this object
     * @return A readable description of this object
     */
    public String getDescription() {
    	return "OpenPGP ASCII Public File URL Reader";
    }

}
