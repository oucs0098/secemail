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
 * <p>Send an email.</p>
 * <p>This command sends an email which is intercepted by the proxy server, encrypted / signed, 
 * and then sent to the email server together with the recipients etc. </p>
 * <p>A final success code is then sent back to the client.</p>
 * <p>See protocol spec for caveats.</p>
 */
public class IPTPSendData extends IPTPCommand {
    
    /** The message. */
    private String message;
    
    /** Creates a new instance of IPTPSendData */
    public IPTPSendData(String data) {
        setMessageData(data);
    }
    
    /** Set the message data. */
    protected void setMessageData(String data) {
        //message = new String(data);
        message = data;
    }
    
    /** Get the message data. */
    public String getMessageData() {
        return message;
    }
    
}
