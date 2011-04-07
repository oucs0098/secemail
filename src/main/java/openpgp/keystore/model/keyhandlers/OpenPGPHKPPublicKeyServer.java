package openpgp.keystore.model.keyhandlers;

import java.net.*;
import java.io.*;
import java.util.Iterator;

import openpgp.keystore.*;
import openpgp.keystore.model.*;
import openpgp.keystore.util.StreamHelper;
import core.algorithmhandlers.openpgp.util.*;
import core.keyhandlers.identifiers.*;
import core.keyhandlers.*;
import core.exceptions.*;

/** <p>HKP Public key server.</p>
 * <p>This class implements basic support for the PKS "Horowitz Key Protocol"
 * Server protocol, and is based on the OpenPGPHTTPPublicKeyServer class.</p>
 * <p>The default port for this should be 11371, though the code does not 
 * assume this if you do not set it.</p>
 */
public class OpenPGPHKPPublicKeyServer extends OpenPGPHTTPKeyServer {
    
    /** The root address on the key server for where the "command pages" are,
     * must begin and end with "/". */
    public static final String serverpath = "/pks/";
    
    /** Creates a new instance of OpenPGPHTTPPublicKeyServer */
    public OpenPGPHKPPublicKeyServer() {
    }
    
    /** Creates a new instance of OpenPGPHTTPPublicKeyServer.
     * @param address The address of the server to talk to (without the 
     * "http://").
     * @param port The port on the server to connect to.
     * @param parameters Any extra parameters needed (for example a pass 
     * phrase), may be null.
     */
    public OpenPGPHKPPublicKeyServer(String address, int port, 
    		KeyHandlerParameters parameters) {
        setServer(address, port, parameters);
    }
    
    /** <p>Add a number of keys to the key store.</p>
     * <p>Stores a key in the key store with details specified by idDetails 
     * and parameters as necessary.</p>
     * <p>If a key with the same details already exists it is NOT replaced, 
     * this is up to you to do.</p>
     * <p>FIXME: Currently does not return a success code if key was added / 
     * replaced / whatever. </p>
     * @param key[] The keys to store.
     * @param idDetails[] Information identifying the keys (exactly what info 
     * is provided is dependent on the type of keystore).
     * @param parameters[] Any extra parameters needed, for example pass phrases
     * for secret key stores etc, may be null.
     * @throws KeyHandlerException if something went wrong.
     *
     */
    public void addKeys(KeyObject[] key, KeyIdentifier[] idDetails,
			KeyHandlerParameters[] parameters) throws KeyHandlerException {
        
        try {
        	if (!(key[0] instanceof PrimarySigningKey)) {
        		throw new KeyHandlerException("Unknown KeyObject type found. Object is " +
        				key[0].getClass().getName());
        	}
        	//TODO: convert to using PrimaryKey objects
            
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
            for (int i = 0; i < key.length; ++i) {
            	out.write(Armory.armor(OpenPGPKeyFile.getPublicKeyData(
                		(PrimarySigningKey)key[i], false)).getBytes());
            }
            
            // write tail
            out.write("-----END PGP PUBLIC KEY BLOCK-----\r\n".getBytes());
            
            String querystring = new String("keytext=" + 
            		URLEncoder.encode(out.toString(), "UTF-8"));

            // try sending it off
            URL query = new URL("http", getServerAddress(), getServerPort(),
					serverpath + "add");
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
            	InputStream in = conn.getInputStream();
            	
            	StringBuffer sb = new StringBuffer();
            	String line = null;
            	do {
            		// read in the response from the key server
                    line = StreamHelper.readLine(in);
                    if (line!=null) {
                    	sb.append(line); 
                    	sb.append(" ");
                    }
                } while (line!=null);
            	
            	int start = sb.indexOf("<pre>");
            	sb.delete(0, start + 5);
            	int finish = sb.indexOf("</pre>");
            	sb.delete(finish, sb.length());
            	System.out.println(sb.toString().trim());
                
            } else {
                throw new KeyHandlerException("HTTP Connection to " + 
                		getServerAddress() + ":" + getServerPort() + 
                		" failed with code " + conn.getResponseCode() + 
                		"\r\n\t" + conn.getResponseMessage());
            }

            conn.disconnect();  
        
        } catch (Exception e) {    
            throw new KeyHandlerException(e.getMessage());
        }
    }
    
    /** <p>Change a key handler setting.</p>
     * <p>This method allows you to change a setting of a key handler object, 
     * for example change the passphrase used for unlocking a key.</p>
     * <p>What settings can be changed depend on the type of key handler.</p>
     * @param parameters What to change and the parameters needed.
     * @throws KeyHandlerException if something went wrong.
     *
     */
    public void changeSetting(KeyHandlerParameters parameters) 
    		throws KeyHandlerException {
    }
    
    /** <p>Delete a key matching the given id from a given key store.</p>
     * <p>This method will remove all keys matching the KeyIdentifier object from the 
     * key store, and so care should be taken to be as specific as possible!</p>
     * <p>The actual mechanics of how the key is deleted are of course implementation 
     * dependent, but generally if a key store is a file the key is physically deleted,
     * but if the key store is a server it is generally just revoked.</p>
     * @param id A KeyIdentifier object specifying the key(s) to remove.
     * @param parameters Any extra parameters needed, for example pass phrases for 
     * secret key stores etc, may be null.
     * @return The number of keys removed.
     * @throws KeyHandlerException if something went wrong.
     */
    public int removeKeys(KeyIdentifier id, KeyHandlerParameters parameters) 
    		throws KeyHandlerException {
        return 0;
    }
    
    /** Method to return a readable description of this object
     * @return A readable description of this object
     */
    public String getDescription() {
    	return "OpenPGP HKP Public Key Server";
    }

    /** <p>Look for a key.</p>
     * <p>Looks for a key in the key store as specified by the key identifier.</p>
     * <p>The actual KeyIdentifier class used depends on the type of key being looked 
     * for.</p>
     * @param id The key identifier that specifies the key being looked for. Note, if 
     * OpenPGPKeyIDKeyIdentifier is used, the first 4 bytes of the key ID are ignored
     * by the search.
     * @param parameters Any extra parameters needed, for example pass phrases for 
     * secret key stores etc, may be null.
     * @return An array of KeyData objects that contain (among other things) the key 
     * material, or NULL if no keys matching id could be found.
     * @throws ChecksumFailureException If the key data fails a checksum (usually because
     * the wrong passphrase was supplied).
     * @throws KeyHandlerException if something went wrong.
     */
	public KeyObject[] findKeys(KeyIdentifier id, KeyHandlerParameters parameters) 
			throws KeyHandlerException, ChecksumFailureException {
		
		KeyStore keyStore = null;
        
        try {
        
            // how are we searching for key?
            if ((id instanceof OpenPGPStandardKeyIdentifier) || 
            		(id instanceof OpenPGPKeyIDKeyIdentifier) ||
            		(id instanceof OpenPGPFreeTextKeyIdentifier)) {
                
                // convert key id to printable version
                String searchid = "";
                if (id instanceof OpenPGPKeyIDKeyIdentifier) {
                    searchid="0x";
                    for (int cnt = 4; cnt < id.getDefaultID().length; cnt++) {
                    	searchid += Integer.toHexString(
                    			id.getDefaultID()[cnt] & 0xFF);
                    }
                } else {
                	searchid = new String(id.getDefaultID());
                }

                // lookup?op=get&search= url encoded key id
                URL query = new URL("http", getServerAddress(), getServerPort(),
                		serverpath + "lookup?op=get&search=" + 
                		URLEncoder.encode(searchid, "UTF-8"));
                debug.Debug.println(2, "URL=" + query.toString());
                HttpURLConnection conn = (HttpURLConnection)query.openConnection();
                conn.connect();

                // read result and parse (quick and dirty method which uses the
                // code in the KeyFile branch.)
                if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
                    KeyParser tmp = new KeyParser();
                    // delegate decoding to the keyring parser
                    keyStore = tmp.getKeyStore(
                    		getPublicKeyBytes(conn.getInputStream()), new byte[0]);
                } else {
                    throw new KeyHandlerException("HTTP Connection to " + 
                    		getServerAddress() + ":" + getServerPort() + 
                    		" failed with code " + conn.getResponseCode() +
                    		"\r\n\t" + conn.getResponseMessage());
                }
                
                conn.disconnect();

            } else {
                throw new KeyHandlerException("Unrecognised key identifier given");
            }
  
        } catch (Exception e) {
            throw new KeyHandlerException(e.getMessage());
        }
        
        KeyObject[] keyObjects = null;
        if (keyStore != null) {
        	// convert the keys into the correct format for returning
        	keyObjects = new KeyObject[keyStore.getAllKeysCount()];
        	int index = 0;
        	for (Iterator it = keyStore.getAllKeysIterator();it.hasNext();) {
        		keyObjects[index++] = (PrimarySigningKey)it.next();
        	}
        }
        return keyObjects;
	}
	
	/** Method to read public keys from the OpenPGP ASCII stream
	 * @return a byte array possibly containing public keys
	 */
    private byte[] getPublicKeyBytes(InputStream stream) 
    		throws IOException, KeyHandlerException {
     
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            
            // read and decode ascii stream
            String line = null;
            do {
                line = StreamHelper.readLine(stream);

                // read until header
                if (line!=null) {
                    if (line.compareTo("-----BEGIN PGP PUBLIC KEY BLOCK-----")==0) {

                        ByteArrayOutputStream tmp = new ByteArrayOutputStream();

                        // read until blank line
                        line = StreamHelper.readLine(stream);
                        while ((line!=null) && (line.length()>0))
                            line = StreamHelper.readLine(stream);

                        // read body
                        line = StreamHelper.readLine(stream);
                        while ((line!=null) && (line.compareTo(
                        		"-----END PGP PUBLIC KEY BLOCK-----")!=0)) {
                            tmp.write(line.getBytes()); 
                            tmp.write("\r\n".getBytes());
                            line = StreamHelper.readLine(stream);
                        }

                        // Process key data
                        if (line.compareTo(
                        		"-----END PGP PUBLIC KEY BLOCK-----")==0) {
                            out.write(Armory.disarm(
                            		new String(tmp.toString())));
                        } else {
                            throw new AlgorithmException(
                            		"ASCII key file is incomplete.");
                        }
                    }
                }

            } while (line!=null);
            
            stream.close();
            return out.toByteArray();
            
        } catch (Exception e) {
            throw new KeyHandlerException(e.getMessage());
        }
    }
 
}
