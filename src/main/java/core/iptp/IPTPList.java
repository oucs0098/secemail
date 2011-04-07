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

package core.iptp;

/**
 * <p>Request details about a message, or all messages if no parameters were set.</p>
 * <p>Expects a multiline response if the command was successful.</p>
 */
public class IPTPList extends IPTPCommand {

    /** The message to retrieve info on.*/
    private int messageno;

    /** <p>Creates a new instance of IPTPList (equiv to "list" in POP3).</p> */
    public IPTPList() {
        setExpectingMultilineResponse(true);
        setMessageNo(-1);
    }

    /** <p>Creates a new instance of IPTPList with a given message number (equiv to "list x" in POP3).</p>
    * @param messno is the message to retrieve details of. Set to -1 for no parameters or use default contructor.
    */
    public IPTPList(int messno) {
        setMessageNo(messno);
        setExpectingMultilineResponse(false);
    }

    /** Set the message number to retrieve. */
    protected void setMessageNo(int messno) {
        messageno = messno;
    }

    /** Get the message number or -1 if not set*/
    public int getMessageNo() {
        return messageno;
    }
}
