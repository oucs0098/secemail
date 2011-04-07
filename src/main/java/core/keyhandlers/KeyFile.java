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
import java.lang.String;
import java.util.Random;
import java.io.*;

/**
 * <p>A root class for all key handlers implemented using a local file.</p>
 * <p>Provides a syntactic distinction between key handlers that talk to files and those which
 * talk to key servers.</p>
 */
public abstract class KeyFile extends KeyHandler {
    
    /** File name of the key store. */
    private String fileName;
    
    /** Any extra information needed to open the file. */
    private KeyHandlerParameters fileParameters;
    
    /** Creates a new instance of KeyFile */
    public KeyFile() {
    }
    
    /** Creates a new instance of KeyFile. 
     * @param filename The path and filename of the key store.
     * @param parameters Any extra parameters needed (for example a pass phrase), may be null.
     * @throws IOException if there was a problem.
     */
    public KeyFile(String filename, KeyHandlerParameters parameters){
        setFile(filename, parameters);
    }

    /**
     * <p>Set the file to use.</p>
     * <p>This method points the key handler at a given file. It does not actually open the file, this should be
     * done by the appropriate search method implementations.</p>
     * @param filename The path and filename of the key store.
     * @param parameters Any extra parameters needed (for example a pass phrase), may be null.
     */
    public void setFile(String filename, KeyHandlerParameters parameters) {
        fileName = filename;
        fileParameters = parameters;
    }
    
    /**
     * <p>Set the file to use with no parameters.</p>
     * <p>This method points the key handler at a given file. It does not actually open the file, this should be
     * done by the appropriate search method implementations.</p>
     * @param filename The path and filename of the key store.
     */
    public void setFile(String filename) {
        setFile(filename, null);
    }
    
    /** Return any extra information previously stored by setFile. */
    public KeyHandlerParameters getFileParameters() {
        return fileParameters;
    }
    
    /** Return the file name of the key store. */
    public String getFileName() {
        return fileName;
    }

    /**
     * <p>Override toString to allow the Key handler to be rendered nicely
     * in a swing list box.</p>
     * <p>This should be called from the subclass, which should prefix this
     * string with a readable description of itself</p>
     */
    public String toString() {
        return getDescription() + " (" + getFileName() + ")";
    }
    
    /** counter, generates numbers for temp files */
    private static int counter = -1;
    
    /** sequential 16-bit number generator (room for number growth) */
    protected static int generateNumber() {
    	synchronized("NUMLOCK") {
    		if (counter == -1) {
                counter = new Random().nextInt() & 0xffff;
            }
            return ++counter;
    	}
    }
    
}
