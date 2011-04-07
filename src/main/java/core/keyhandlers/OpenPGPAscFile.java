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

/**
 * <p>Basic support for the PGP asc file format.</p>
 */
public abstract class OpenPGPAscFile extends OpenPGPKeyring {
    
    /** Creates a new instance of OpenPGPAscFileReader */
    public OpenPGPAscFile() {
    }
    
    /** Creates a new instance of OpenPGPAscFile */
    public OpenPGPAscFile(String filename, KeyHandlerParameters parameters){
        super(filename, parameters);
    }

    /**
     * <p>A quick method used by findKeys to simplify the reading of data from other sources.</p>
     */
    public KeyObject[] findKeys(InputStream stream, KeyIdentifier id, KeyHandlerParameters parameters) throws ChecksumFailureException, KeyHandlerException {
     
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            
            // read and decode ascii file
            String line = null;
            do {
                
                line = readLine(stream);

                // read until header
                if (line!=null) {
                    if ((line.compareTo("-----BEGIN PGP PUBLIC KEY BLOCK-----")==0) 
                        || (line.compareTo("-----BEGIN PGP PRIVATE KEY BLOCK-----")==0)) {

                            ByteArrayOutputStream tmp = new ByteArrayOutputStream();

                            // read until blank line
                            line = readLine(stream);
                            while ((line!=null) && (line.length()>0))
                                line = readLine(stream);

                            // read body
                            line = readLine(stream);
                            while ((line!=null) && 
                                ((line.compareTo("-----END PGP PUBLIC KEY BLOCK-----")!=0) && 
                                (line.compareTo("-----END PGP PRIVATE KEY BLOCK-----")!=0))) {
                                    tmp.write(line.getBytes()); tmp.write("\r\n".getBytes());

                                    line = readLine(stream);
                            }

                            // Process key data
                            if ((line.compareTo("-----END PGP PRIVATE KEY BLOCK-----")==0) ||
                                (line.compareTo("-----END PGP PUBLIC KEY BLOCK-----")==0)){
                                out.write(Armory.disarm(new String(tmp.toString())));
                            } else {
                                throw new AlgorithmException("ASCII key file is incomplete.");
                            }
                    }
                }

            } while (line!=null);
            
            stream.close();
            
            // delegate decoding to superclass
            return super.findKeys(new ByteArrayInputStream(out.toByteArray()), id, parameters);
            
        } catch (Exception e) {
            throw new KeyHandlerException(e.getMessage());
        }
    }
    
    /**
     * <p>Delete a key matching the given id from a given key store.</p>
     * <p>This method simply removes the key file if the ID is found in the file.</p>
     * @param id A KeyIdentifier object specifying the key(s) to remove.
     * @param parameters Use the same parameter objects as you would for findKeys. This is a bit of a kludge.
     * @return The number of keys removed.
     * @throws KeyHandlerException if something went wrong.
     */
    public int removeKeys(KeyIdentifier id, KeyHandlerParameters parameters) throws KeyHandlerException {
        
        try {
            KeyObject[] keys = findKeys(id, parameters);

            if (keys!=null) {
                File f = new File(getFileName());

                if (!f.delete())
                    throw new KeyHandlerException("Failed to delete keyfile!");

                return keys.length;
            }

            return 0;
        } catch (Exception e) {
            throw new KeyHandlerException(e.getMessage());
        }
    }
    
    /**
     * <p>Change a key handler setting.</p>
     * <p>This method allows you to change a setting of a key handler object, for example change the passphrase used for unlocking a key.</p>
     * <p>What settings can be changed depend on the type of key handler.</p>
     * @param parameters What to change and the parameters needed.
     * @throws KeyHandlerException if something went wrong.
     */
    public void changeSetting(KeyHandlerParameters parameters) throws KeyHandlerException {
    }   
    
    /** 
     * <p>Read a full line from an input stream, returning it in a string. </p>
     * <p>Written because there are issues attached to using buffered readers in this context. </p>
     * @param in The stream to read from.
     * @return the line, or a zero length string if like was empty (other than end of line chars).
     */
    protected String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        
        int b = in.read();
        while ( (b != '\r') && (b != '\n') && (b != -1)) {
            out.write(b);
            b = in.read();
        }

        if (b == '\r') in.read(); // if there is a \r then next line will be a \n.. so skip it

        if ((b==-1) && (out.size()==0)) {
            return null;
        }
        
        return out.toString();
    }
}
