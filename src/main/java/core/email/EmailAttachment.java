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

package core.email;
import core.exceptions.*;
import core.email.util.*;
import java.lang.String;
import java.io.*;
import java.util.Vector;

/**
 * <p>A class representing an email attachment. </p>
 * <p>This class represents the raw binary form of a file attachment.</p>
 */
public class EmailAttachment extends MimeComponent {
 
    /** Filename of attachement. */
    private String fileName;
    
    /** 
     * <p>Creates a new empty instance of Attachment.</p>
     */
    public EmailAttachment() {
    }
    
    /** 
     * <p>Creates a new instance of Attachment.</p>
     * <p>This method will extract filename and encoding information from the supplied headers, but no decoding is performed. 
     * Therefore, if the headers state that the attachment is base64 encoded, you must perform the encoding decoding yourself.</p>
     * @param headers[] Mime headers.
     * @param data[] The file data (encoded according to headers).
     * @throws EmailDataFormatException if the attachment could not be processed.
     */
    public EmailAttachment(EmailHeader [] headers, byte[] data) throws EmailDataFormatException {
        EmailHeader encodingtype = null;
        EmailHeader contentdisp = null;
        
        String filename;
        
        // extract attachment header information
        for (int n = 0; n < headers.length; n++) {
            if (headers[n].getTagName().compareToIgnoreCase("Content-Disposition")==0)
                contentdisp = headers[n];
        }
        
        // if attachment, construct attachment else add to body.
        if ((contentdisp!=null) && ((contentdisp.getTagValue().toLowerCase().indexOf("attachment")!=-1) || (contentdisp.getTagValue().toLowerCase().indexOf("inline")!=-1))) {
            // this is an attachment

            // extract filename
            try {
                filename = contentdisp.getTagValue().substring(contentdisp.getTagValue().indexOf("filename=\"")+10);
                filename = filename.substring(0,filename.indexOf("\""));    
            } catch (IndexOutOfBoundsException i) {
                throw new EmailDataFormatException("Could not extract filename from attachment");
            }

        } else {
            // this isn't an attachment
            throw new EmailDataFormatException("Supplied attachment data does not appear to be an attachment");
        }

        // store attachment info
        setHeaders(headers);
        setFilename(filename);
        setData(data);
    }

    /** Set the filename. */
    protected void setFilename(String filename) {
        fileName = filename;
    }
    
    /** Return the filename of the attachment. */
    public String getFilename() {
        return fileName;
    }

    /**
     * <p>Get the email attachment in its encoded form.</p> 
     * <p>Returns the encoded form of the email attachment in its default format (BASE64).</p>
     * @throws EmailDataFormatException if there was a problem constructing the component.
     */
    public byte [] getBytes() throws EmailDataFormatException {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            // output headers
            EmailHeader [] headers = getHeaders();
            if ((headers != null) && (headers.length>0))
                for (int n = 0; n < headers.length; n++) {
                    out.write(headers[n].toString().getBytes());
                    out.write("\r\n".getBytes());
                }

            out.write("\r\n".getBytes());

            // output file data
            out.write(getData());

            return out.toByteArray();
        } catch (Exception e) {
            throw new EmailDataFormatException(e.getMessage());
        }
    }
    
}
