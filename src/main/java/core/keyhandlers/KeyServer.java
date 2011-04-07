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

/**
 * <p>A root class for all key handlers implemented using a remote key server.</p>
 * <p>Provides a syntactic distinction between key handlers that talk to files and those which
 * talk to key servers.</p>
 * <p>Note, if the server you're connecting to requires a username / password login you should provide those
 * in the parameters of the constructor and store them until needed. This will require less work on your 
 * part to integrate the new server with the system.</p>
 */
public abstract class KeyServer extends KeyHandler {

    /** Server address of the key store. */
    private String serverAddress;
    
    /** The port to connect to. */
    private int serverPort;
    
    /** Any extra information needed to connect to the server. */
    private KeyHandlerParameters serverParameters;
    
    /** Creates a new instance of KeyServer */
    public KeyServer() {
    }
    
    /** Creates a new instance of KeyServer.
     * @param address The address of the server to talk to.
     * @param port The port on the server to connect to.
     * @param parameters Any extra parameters needed (for example a pass phrase), may be null.
     */
    public KeyServer(String address, int port, KeyHandlerParameters parameters) {
        setServer(address, port, parameters);
    }

    /**
     * <p>Set the server to use.</p>
     * <p>This method points the key handler at a given server. It does not actually connect to the server, this should be
     * done by the appropriate search method implementations.</p>
     * @param address The address of the server to talk to.
     * @param port The port on the server to connect to.
     * @param parameters Any extra parameters needed (for example a pass phrase), may be null.
     */
    public void setServer(String address, int port, KeyHandlerParameters parameters) {
        serverAddress = address;
        serverPort = port;
        serverParameters = parameters;
    }
    
    /**
     * <p>Set the server to use with no parameters.</p>
     * <p>This method points the key handler at a given server. It does not actually connect to the server, this should be
     * done by the appropriate search method implementations.</p>
     * @param address The address of the server to talk to.
     * @param port The port on the server to connect to.
     */
    public void setServer(String address, int port) {
        setServer(address, port, null);
    }
    
    /** Return the server address of the key store. */
    public String getServerAddress() {
        return serverAddress;
    }
    
    /** Return the server port. */
    public int getServerPort() {
        return serverPort;
    }
    
    /** Return any server parameters as registered by setServer. */
    public KeyHandlerParameters getServerParameters() {
        return serverParameters;
    }
    
    /** <p>Override toString to allow the Key handler to be rendered nicely
     * in a swing list box or combo box.</p>
     * <p>This should be called from the subclass, which should prefix this
     * string with a readable description</p>
     */
    public String toString() {
        return getDescription() + " (" + getServerAddress() + ":" + 
        		getServerPort() + ")";
    }
}
