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
import core.exceptions.KeyHandlerException;
import core.exceptions.ChecksumFailureException;
import system.ConfigurationData;
import java.security.Key;
import java.lang.ClassNotFoundException;
import java.lang.String;
import java.util.Vector;

/**
 * <p>Root class for all key handlers.</p>
 * <p>Defines a common interface for all key handler objects, providing methods for seaching
 * key storage entities for keys.</p>
 */
public abstract class KeyHandler {
    
    /** Creates a new instance of KeyHandler */
    public KeyHandler() {
    }

    /**
     * <p>Look for a key.</p>
     * <p>Looks for a key in the key store as specified by the key identifier.</p>
     * <p>The actual KeyIdentifier class used depends on the type of key being looked for.</p>
     * @param id The key identifier that specifies the key being looked for. 
     * @param parameters Any extra parameters needed, for example pass phrases for secret key stores etc, may be null.
     * @return An array of KeyData objects that contain (among other things) the key material, or NULL if no keys matching id could be found.
     * @throws ChecksumFailureException If the key data fails a checksum (usually because the wrong passphrase was supplied).
     * @throws KeyHandlerException if something went wrong.
     */
    public abstract KeyObject[] findKeys(KeyIdentifier id, KeyHandlerParameters parameters) throws KeyHandlerException, ChecksumFailureException;
    
    /**
     * <p>Add a number of keys to the key store.</p>
     * <p>Stores a key in the key store with details specified by idDetails and parameters as necessary.</p>
     * <p>If a key with the same details already exists it is NOT replaced, this is up to you to do.</p>
     * @param key[] The keys to store.
     * @param idDetails[] Information identifying the keys (exactly what info is provided is dependent on the type of keystore).
     * @param parameters[] Any extra parameters needed, for example pass phrases for secret key stores etc, may be null.
     * @throws KeyHandlerException if something went wrong.
     */
    public abstract void addKeys(KeyObject key[], KeyIdentifier idDetails[], KeyHandlerParameters parameters[]) throws KeyHandlerException;
    
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
     */
    public abstract int removeKeys(KeyIdentifier id, KeyHandlerParameters parameters) throws KeyHandlerException;

    /**
     * <p>Change a key handler setting.</p>
     * <p>This method allows you to change a setting of a key handler object, for example change the passphrase used for unlocking a key.</p>
     * <p>What settings can be changed depend on the type of key handler.</p>
     * @param parameters What to change and the parameters needed.
     * @throws KeyHandlerException if something went wrong.
     */
    public abstract void changeSetting(KeyHandlerParameters parameters) throws KeyHandlerException;
    
    /**
     * <p>Returns a readable description of this class, to be used for 
     * user-oriented display (e.g. in GUI list boxes etc)</p>
     * @return A description of the entity
     */
    public abstract String getDescription();
    
    /**
     * <p>Override toString to allow the Key handler to be rendered nicely in a swing list box.</p>
     */
    public String toString() {
        return "Unrecognised key handler (" + this.getClass().getName() + ")";
    }
    
    /** <p>Load a list of key servers from a config file.</p>
     * @param properties The config file inwhich data is stored.
     * @param prefix The prefix of the data in the config file up to and including
     * the "." but not including the priority, eg "keymanager.openpgp.publiclist."
     * would load "keymanager.openpgp.publiclist.1.type" etc...
     * @return An array in order of priority of the loaded list.
     * @throws ClassNotFoundException if the key handler class couldn't be found.
     * @throws KeyHandlerException if something else went wrong.
     */
    public static KeyHandler [] loadKeysourceList(ConfigurationData properties, String prefix) throws KeyHandlerException, ClassNotFoundException {
        
        try {
            Vector v = new Vector(); // storage for the class

            int n = 1;

            while (properties.getSetting(prefix + n + ".type","").compareTo("")!=0) {

                // get class name
                String classname = properties.getSetting(prefix + n + ".type","");

                // get class 
                Class c = Class.forName(classname);               
                Object o = c.newInstance();
               
                // basic class type test
                if (o instanceof KeyHandler) {
                    // load the respective classes
                    
                    
                    // TODO: Place special case initialisation here, before general cases
                    
                    
                    // general cases
                    if (o instanceof KeyFile) {
                        // Create general file server
                        
                        KeyFile kf = (KeyFile)o;
                        
                        String filename = properties.getSetting(prefix + n + ".filename", "");
                        if (filename.compareTo("")==0)
                            throw new KeyHandlerException("KeyFile handler requires a filename.");
                        
                        kf.setFile(filename, null);
                        
                        v.add(o);
                        
                    } else if (o instanceof KeyServer) {
                        // Create general key server
                        
                        KeyServer ks = (KeyServer)o;
                        
                        String address = properties.getSetting(prefix + n + ".serveraddress", "");
                        if (address.compareTo("")==0)
                            throw new KeyHandlerException("KeyServer handler requires a server address.");
                        
                        String portstr = properties.getSetting(prefix + n + ".serverport", "");
                        if (portstr.compareTo("")==0)
                            throw new KeyHandlerException("KeyServer handler requires a server port.");
                        
                        ks.setServer(address, Integer.parseInt(portstr), null);
                        
                        v.add(o);
                        
                    } else {
                        throw new KeyHandlerException("Unrecognised KeyHandler");
                    }
                    
                    
                } else {
                    throw new KeyHandlerException("Key handler " + n + " is not a KeyHandler object.");
                }

                n++;
            }

            // return list
            if (v.size()>0) {
                KeyHandler [] tmp = new KeyHandler[v.size()];
                for (int na = 0; na<v.size(); na++) {
                    tmp[na] = (KeyHandler)v.elementAt(na);
                }
                
                return tmp;
            }
            
            return null;
            
        } catch (ClassNotFoundException cnfe) {
            throw cnfe;
        } catch (Exception e) {
            throw new KeyHandlerException(e.getMessage());
        }
    }
}
