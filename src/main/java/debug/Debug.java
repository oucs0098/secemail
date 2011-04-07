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

package debug;
import java.io.PrintStream;
import java.lang.String;

/**
 * <p>Simple debugging utility class.</p>
 */
public class Debug {
    
    /** Debug level */
    private static int level;
    
    /** 
     * <p>Set debug level.</p>
     * <p>0 - off, 1, 2, 3 etc higher levels of detail.</p>
     */
    public static void setLevel(int lvl) {
        level = lvl;
    }
    
    /** <p>Print some output data to the given stream.</p>
     * @param stream Where to write the text.
     * @param lvl The debug level of this message - message won't be printed unless lvl is >= level set buy setLevel.
     * @param data String to output.
     */
    public static void println(PrintStream stream, int lvl, String data) {
        if (level>=lvl) 
            stream.println(data);
    }
    
    /** <p>Print some output data to standard out.</p>
     * @param lvl The debug level of this message - message won't be printed unless lvl is >= level set buy setLevel.
     * @param data String to output.
     */
    public static void println(int lvl, String data) {
        println(System.out, lvl, data);
    }
    
    /** <p>Print some hex data to the given stream.</p>
     * @param stream Where to write the text.
     * @param lvl The debug level of this message - message won't be printed unless lvl is >= level set buy setLevel.
     * @param data array of byte holding the raw data you want to dump as hex.
     */
    public static void hexDump(PrintStream stream, int lvl, byte []data) {
        if (level>=lvl) {
            for (int cnt = 0; cnt < data.length; cnt++)
                stream.print(Integer.toHexString(data[cnt] & 0xFF).toUpperCase() + " ");

            stream.println();
        }
    }
    
    /** <p>Print some hex data to the standard out.</p>
     * @param lvl The debug level of this message - message won't be printed unless lvl is >= level set buy setLevel.
     * @param data array of byte holding the raw data you want to dump as hex.
     */
    public static void hexDump(int lvl, byte []data) {
        hexDump(System.out, lvl, data);
    }
    
    public static void hexDump(int lvl, byte data) {
        if (level>=lvl) {
           System.out.print(Integer.toHexString(data & 0xFF).toUpperCase() + " ");
        }
    }
}
