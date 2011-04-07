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
import java.net.*;
import java.io.*;
import java.util.Vector;
import core.algorithmhandlers.openpgp.util.*;
import core.keyhandlers.parameters.*;
import core.keyhandlers.identifiers.*;
import core.keyhandlers.keydata.*;
import core.exceptions.*;

/**
 * <p>HTTP Public key server.</p>
 * <p>This class implements basic support for the PKS "Horowitz Key Protocol" Server protocol.</p>
 * <p>The default port for this should be 11371, though the code does not assume this if you do not set it.</p>
 */
public class OpenPGPHTTPPublicKeyServer extends OpenPGPHTTPKeyServer {
    
    /** The root address on the key server for where the "command pages" are, must begin and end with "/". */
    public static final String serverpath = "/pks/";
    
    /** Creates a new instance of OpenPGPHTTPPublicKeyServer */
    public OpenPGPHTTPPublicKeyServer() {
    }
    
    /** Creates a new instance of OpenPGPHTTPPublicKeyServer.
     * @param address The address of the server to talk to (without the "http://").
     * @param port The port on the server to connect to.
     * @param parameters Any extra parameters needed (for example a pass phrase), may be null.
     */
    public OpenPGPHTTPPublicKeyServer(String address, int port, KeyHandlerParameters parameters) {
        setServer(address, port, parameters);
    }
    
    /** <p>Add a number of keys to the key store.</p>
     * <p>Stores a key in the key store with details specified by idDetails and parameters as necessary.</p>
     * <p>If a key with the same details already exists it is NOT replaced, this is up to you to do.</p>
     * <p>FIXME: Currently does not return a success code if key was added / replaced / whatever. </p>
     * @param key[] The keys to store.
     * @param idDetails[] Information identifying the keys (exactly what info is provided is dependent on the type of keystore).
     * @param parameters[] Any extra parameters needed, for example pass phrases for secret key stores etc, may be null.
     * @throws KeyHandlerException if something went wrong.
     *
     */
    public void addKeys(KeyObject[] key, KeyIdentifier[] idDetails, KeyHandlerParameters[] parameters) throws KeyHandlerException {
        
        try {
        	if (!(key instanceof KeyData[])) {
        		throw new KeyHandlerException("Unknown KeyObject type found");
        	}
        	
            // construct ascii armored key
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            
            out.write("-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n".getBytes());
            out.write("Version: Secure Email Proxy v".getBytes()); 
            out.write(core.CoreVersionInfo.version.getBytes()); 
            out.write("\r\n".getBytes());
            out.write("Comment: Oxford Brookes Secure Email Project (".getBytes()); 
            out.write(core.CoreVersionInfo.website.getBytes()); 
            out.write(")\r\n".getBytes());
            out.write("\r\n".getBytes());
            
            // write keyring in ascii armored format
            OpenPGPAscPublicFile tmp = new OpenPGPAscPublicFile();
            out.write(Armory.armor(tmp.addKeyData(key, idDetails, parameters)).getBytes());
            
            // write tail
            out.write("-----END PGP PUBLIC KEY BLOCK-----\r\n".getBytes());
            
            String querystring = new String("keytext=" + URLEncoder.encode(out.toString(), "UTF-8"));

            // try sending it off
            URL query = new URL("http", getServerAddress(), getServerPort(), serverpath + "add");
            HttpURLConnection conn = (HttpURLConnection)query.openConnection();
            conn.setDoOutput(true);
            
            conn.setRequestMethod("POST");
            
            OutputStream connOut = conn.getOutputStream();
            connOut.write(querystring.getBytes());
            connOut.close();
            
            // connect & get the result of the query.
            conn.connect();
            
            if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
                
                // parse response for success 
                
                // TODO: Currently does not return a success code if key was added / replaced / whatever. 
                
                
                
            } else {
                throw new KeyHandlerException("HTTP Connection to " + getServerAddress() + ":" + getServerPort() + " failed with code " + conn.getResponseCode() + "\r\n\t" + conn.getResponseMessage());
            }

            conn.disconnect();  
        
        } catch (Exception e) {    
            throw new KeyHandlerException(e.getMessage());
        }
    }
    
    /** <p>Change a key handler setting.</p>
     * <p>This method allows you to change a setting of a key handler object, for example change the passphrase used for unlocking a key.</p>
     * <p>What settings can be changed depend on the type of key handler.</p>
     * @param parameters What to change and the parameters needed.
     * @throws KeyHandlerException if something went wrong.
     *
     */
    public void changeSetting(KeyHandlerParameters parameters) throws KeyHandlerException {
    }
    
    /** <p>Look for a key.</p>
     * <p>Looks for a key in the key store as specified by the key identifier.</p>
     * <p>The actual KeyIdentifier class used depends on the type of key being looked for.</p>
     * @param id The key identifier that specifies the key being looked for. Note, if OpenPGPKeyIDKeyIdentifier is used, the first 4 bytes of the key ID are ignored by the search.
     * @param parameters Any extra parameters needed, for example pass phrases for secret key stores etc, may be null.
     * @return An array of KeyData objects that contain (among other things) the key material, or NULL if no keys matching id could be found.
     * @throws ChecksumFailureException If the key data fails a checksum (usually because the wrong passphrase was supplied).
     * @throws KeyHandlerException if something went wrong.
     *
     */
    public KeyObject[] findKeys(KeyIdentifier id, KeyHandlerParameters parameters) throws KeyHandlerException, ChecksumFailureException {
        
        Vector keys = new Vector();
        
        try {
        
            // how are we searching for key?
            if ((id instanceof OpenPGPStandardKeyIdentifier) || (id instanceof OpenPGPKeyIDKeyIdentifier)) {
                // fetch a specific key id
                
                // convert key id to printable version
                String searchid = "";
                if (id instanceof OpenPGPStandardKeyIdentifier) {
                    searchid = new String(id.getDefaultID());
                } else if (id instanceof OpenPGPKeyIDKeyIdentifier) {
                    searchid="0x";
                    for (int cnt = 4; cnt < id.getDefaultID().length; cnt++)
                        searchid += Integer.toHexString(id.getDefaultID()[cnt] & 0xFF);
                }

                // lookup?op=get&search= url encoded key id
                URL query = new URL("http", getServerAddress(), getServerPort(), serverpath + "lookup?op=get&search=" + URLEncoder.encode(searchid, "UTF-8"));
                HttpURLConnection conn = (HttpURLConnection)query.openConnection();
                conn.connect();

                // read result and parse (quick and dirty method which uses they code in the KeyFile branch.)
                if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
                    OpenPGPAscPublicFile tmp = new OpenPGPAscPublicFile();
                    KeyObject[] keydata = tmp.findKeys(conn.getInputStream(), id, null);

                    if (keydata!=null) {
                        for (int n = 0; n < keydata.length; n++) {
                            keys.add(keydata[n]);
                        }
                    }
                } else {
                    throw new KeyHandlerException("HTTP Connection to " + getServerAddress() + ":" + getServerPort() + " failed with code " + conn.getResponseCode() + "\r\n\t" + conn.getResponseMessage());
                }
                
                conn.disconnect();

            } else {
                throw new KeyHandlerException("Unrecognised key identifier given");
            }
  
        } catch (Exception e) {
            throw new KeyHandlerException(e.getMessage());
        }
        
        // return keys (or null if no keys found)
        if (keys.size()>0) {
            KeyData keydata[] = new KeyData[keys.size()];
            for (int n = 0; n < keydata.length; n++) {
                keydata[n] = (OpenPGPKeyData)keys.get(n);
            }
        
            return keydata;    
        } 
        
        return null;
    }
    
    /**
     * <p>Delete a key matching the given id from a given key store.</p>
     * <p>This method will remove all keys matching the KeyIdentifier object from the key store, and so
     * care should be taken to be as specific as possible!</p>
     * <p>The actual mechanics of how the key is deleted are of course implementation dependent, but generally if a key store
     * is a file the key is physically deleted, but if the key store is a server it is generally just revoked.</p>
     * @param id A KeyIdentifier object specifying the key(s) to remove.
     * @param parameters Any extra parameters needed, for example pass phrases for secret key stores etc, may be null.
     * @return The number of keys removed.
     * @throws KeyHandlerException if something went wrong.
     *
     */
    public int removeKeys(KeyIdentifier id, KeyHandlerParameters parameters) throws KeyHandlerException {
        return 0;
    }
    
    /** Method to return a readable description of this object
     * @return A readable description of this object
     */
    public String getDescription() {
    	return "OpenPGP HTTP Public Key Server";
    }
 
}
