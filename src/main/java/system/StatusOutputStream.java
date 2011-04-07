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

package system;
import java.io.*;
import java.lang.*;

/**
 * <p>The SystemOutputStream class is provided to give you a more flexable way of outputting
 * status text.</p>
 * <p>You can give this class to System to let you redirect stdout & stderr to any class that
 * implements the StatusOutputInterface.</p>
 * @see StatusOutputInterface
 */
public class StatusOutputStream extends OutputStream {

    /** Where to write the data. */
    private StatusOutputInterface outputStream;
    /** Text buffer */
    private StringBuffer buffer;

    /** Creates a new instance of StatusOutputStream. */
    public StatusOutputStream(StatusOutputInterface output) {
        outputStream = output;
        buffer = new StringBuffer();
    }

    /** Flush the buffer. */
    public void flush() {
        outputStream.appendStatusText(buffer.toString());
        buffer.delete(0,buffer.length());
    }
    
    /** <p>Write a byte to the stream.</p>
     * <p>Converts param to a string, and writes it to the registered StatusOutputInterface object.</p>
     * <p>To speed up screen writes, this class only flushes the buffer once an end of line character is received.</p>
     * @see StatusOutputInterface#appendStatusText(String)
     */
    public void write(int param) throws java.io.IOException {
        buffer.append((char)param);
        if ( ((param & 0xFF) == 13) || ((param & 0xFF) == 10)) flush(); 
    }

}
