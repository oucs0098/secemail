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
import java.io.*;
import java.util.Vector;
import java.lang.StringBuffer;
import java.util.StringTokenizer;

/**
 * <p>This class is constructed by the email pipes and represents the an email complete
 * with headers inside the proxy.</p>
 */
public class Email
{
    /** Email headers */
    private Vector headers;

    /** Non Mime message body */
    private byte [] body;
    
    /** Mime message body components. */
    private Vector mimeBody;
    
    /** Mime attachments */
    private Vector attachments;

    /** 
     * <p>Create a new Email object with the given email data.</p>
     * <p>The given email data is parsed and header, body and attachments are extracted.</p>
     * <p>Note, if this is a multipart message your email body MUST have a boundary terminator on 
     * the last line.</p>
     * @param email[] A byte array containing the full email.
     * @throws EmailDataFormatException if there was a problem parsing the email.
     */
    public Email(byte [] email) throws EmailDataFormatException {
        parseEmail(email);
    }
    
    /**
     * <p>Create a new Email object that is a copy of another.</p>
     * @param email The email to copy.
     */
    public Email(Email email) {
       
        // copy headers
        headers = (Vector)email.headers.clone();
        
        // copy body
        body = new byte[email.body.length];
        System.arraycopy(email.body, 0, body, 0, email.body.length);
        
        // copy mime body
        if (email.mimeBody!=null)
            mimeBody = (Vector)email.mimeBody.clone();
        
        // copy attachments
        if (email.attachments!=null)
            attachments = (Vector)email.attachments.clone();
    }
    
    /** 
     * Set the non-mime email body to data.
     */
    public void setBody(byte [] data) {
        body = data;
    }
    
    /** 
     * Get the non-mime email body.
     */
    public byte [] getBody() {
        return body;
    }
    
     
    /**
     * <p>Get all the mime body components of this email.</p>
     */
    public MimeComponent [] getMimeBody() {
        if ((mimeBody==null) || (mimeBody.size()==0))
            return null;
        
        MimeComponent [] tmp = new MimeComponent[mimeBody.size()];
        for (int n = 0; n < tmp.length; n++)
            tmp[n] = (MimeComponent)mimeBody.elementAt(n);
        
        return tmp;
    }
    
    /**
     * <p>Set all the mime body components of this email.</p>
     */
    public void setMimeBody(MimeComponent [] components) {
        
        mimeBody=new Vector();
        
        for (int n = 0; n < components.length; n++)
            mimeBody.add(components[n]);
    }
    
    /**
     * <p>Parses the email body and tests whether the email body has a HTML (or whatever) part.</p>
     * @return true if the body is found to be multipart.
     */
    public boolean isMultipartBody() throws EmailDataFormatException {
        
        try {
            EmailHeader head[] = getHeader("content-type");

            // if multipart alternative header return true
            if ( (head!=null) && (head[0].getTagValue().startsWith("multipart/alternative;")) )
                return true;

            // if multipart mixed, move to first break and test for multipart/alternative. return true if there.
           
            if ((mimeBody!=null) && (mimeBody.size()>0))
                for (int n = 0; n < mimeBody.size(); n++) {
                    MimeComponent c = (MimeComponent)mimeBody.elementAt(n);

                    // extract header
                    head = c.getHeader("content-type");

                    // if multipart alternative header return true
                    if ( (head!=null) && (head[0].getTagValue().startsWith("multipart/alternative;")) )
                        return true;
                }
           

            return false;
            
        } catch (Exception e) {
            throw new EmailDataFormatException(e.getMessage());
        }
    }
    
    /** 
     * <p>Parse recipient headers (TO and CC) into an array of strings.</p>
     * <p>Important note: This method will not pick up recipients placed in the BCC field. This 
     * information is stored in the SMTP envelope NOT the email header and so can not be accessed here.</p>
     * @throws EmailDataFormatException if the headers could not be parsed.
     */
    public String [] getRecipients() throws EmailDataFormatException {
        EmailHeader to[] = getHeader("to");
        EmailHeader cc[] = getHeader("cc");
        if (to.length != 1 ) throw new EmailDataFormatException("Email To header is badly formed.");
        if ((cc!=null) && (cc.length > 1 )) throw new EmailDataFormatException("Email To header is badly formed.");
       
        Vector rcpts = new Vector();
        
        String s = to[0].getTagValue();
        if (cc!=null) 
            s += ",\r\n " + cc[0].getTagValue();

        StringBuffer sb = new StringBuffer();
        boolean quoted = false;
        
        // bad way of doing it, but i can't work out the regexp to tokenize a string on ',' where commas between '"' don't count.
        for (int n = 0; n < s.length(); n++) {
            if (s.charAt(n)=='"') quoted = !quoted; // toggle quoted flag (spaces and commas are permitted in quotes)
            
            // tokenize string based on ","
            if (((s.charAt(n)==',') || (n==s.length()-1))&& (!quoted)) {
                // Unquoted comma found
                
                if (s.charAt(n)!=',') sb.append(s.charAt(n)); 

                // remove preceeding whitespaces and carrage returns
                int cnt = 0;
                while (((sb.charAt(cnt)==' ') || (sb.charAt(cnt)=='\t') || (sb.charAt(cnt)=='\r') || (sb.charAt(cnt)=='\n')) && (cnt<sb.length()))
                    cnt++;

                // copy data to recipient array
                rcpts.add(sb.substring(cnt));
                sb = new StringBuffer();
            } else {
                // mid message, add to buffer
                sb.append(s.charAt(n));
            }
        }

        String tmp[] = new String[rcpts.size()];
        for (int n = 0; n < rcpts.size(); n++) 
            tmp[n] = (String)rcpts.elementAt(n);
        
        return tmp;
    }
    
    /** 
     * Return an array containing all email headers in order.
     * @return An array of EmailHeader, or null if no headers are found (shouldn't happen!)
     */
    public EmailHeader [] getHeaderArray() {
        if ((headers == null) || (headers.size()==0))
            return null;
        
        EmailHeader tmp[] = new EmailHeader[headers.size()];
        for (int n = 0; n < headers.size(); n++) 
            tmp[n] = (EmailHeader)headers.elementAt(n);
        
        return tmp;
    }
    
    /** 
     * <p>Return all headers matching a given tag.</p>
     * <p>Note, the search is case insensitive.</p>
     * @return The an array of all matching headers, or null if none found.
     */
    public EmailHeader [] getHeader(String tag) {
        if ((headers == null) || (headers.size()==0))
            return null;
        
        Vector subset = new Vector();
        
        // look for matching tags
        for (int n = 0; n < headers.size(); n++) {
            EmailHeader head = (EmailHeader)headers.elementAt(n);
            if (tag.compareToIgnoreCase(head.getTagName())==0)
                subset.add(head);
        }
        
        // did we find anything? return null if not
        if (subset.size()==0) return null;
        
        // return array of headers
        EmailHeader tmp[] = new EmailHeader[subset.size()];
        for (int n = 0; n < subset.size(); n++) 
            tmp[n] = (EmailHeader)subset.elementAt(n);
        
        return tmp;
     
    }
    
    /**
     * <p>Set a header.</p>
     * <p>If the tag exists, its value is modified. Otherwise it is added to the end.</p>
     * <p>Note that only the first instance is changed, and the search is case insensitive.</p>
     * @param tag The tag.
     * @param value The value.
     */
    public void setHeader(String tag, String value) {
        
        if ((headers==null) || (getHeader(tag)==null)) {
            // tag does not already exist, add it
            if (headers == null) headers = new Vector();
            headers.add(new EmailHeader(tag, value));
        } else {
            for (int n = 0; n < headers.size(); n++) {
                EmailHeader head = (EmailHeader)headers.elementAt(n);
                if (tag.compareToIgnoreCase(head.getTagName())==0) {
                    head.setTagValue(value);
                    headers.set(n, head);
                    return;
                }
            }
        }
    }
    
    /**
     * <p>Return a list of all attachments, or null if there are no attachments.</p>
     */
    public EmailAttachment[] getAttachments() {
        if ((attachments == null) || (attachments.size()==0))
            return null;
        
        EmailAttachment tmp[] = new EmailAttachment[attachments.size()];
        for (int n = 0; n < attachments.size(); n++) 
            tmp[n] = (EmailAttachment)attachments.elementAt(n);
        
        return tmp;
    }
    
    /**
     * <p>Add an attachment to the email.</p>
     * <p>Note that if the email does not initially contain attachments it will be 
     * necessary to modify the headers, adding the appropriate boundary marker and content type. </p>
     */
    public void addAttachment(EmailAttachment attachment) {
        if (attachments == null) attachments = new Vector();
        
        attachments.add(attachment);
    }
    
    /**
     * <p>Remove a given attachment.</p>
     * <p>Note that this method does not modify any of the headers, so if you delete the last file - unless you add a 
     * new attachment or modify the headers the email will be invalid.</p>
     */
    public void removeAttachment(String filename) {
        if (attachments!=null) {
            for (int n=0; n<attachments.size(); n++) {
                EmailAttachment tmp = (EmailAttachment)attachments.elementAt(n);
                if (tmp.getFilename().compareTo(filename)==0)
                    attachments.removeElementAt(n);
                
            }
        }
    }
    
    /**
     * <p>Purge all attachments from email.</p>
     * <p>Note that this method does not modify any of the headers, so unless you add a new attachment or modify the headers
     * the email will be invalid.</p>
     */
    public void purgeAttachments() {
        attachments = new Vector();
    }
   
    /**
     * <p>Parse an email into header, body and attachments.</p>
     * @param email[] A byte array containing the full email.
     * @throws EmailDataFormatException if there was a problem parsing the email.
     */
    protected void parseEmail(byte [] email) throws EmailDataFormatException {
        
        try {
            
            ByteArrayInputStream in = new ByteArrayInputStream(email);
            
            // pass email through mime decoder
                MimeComponent mimeparts = MimeComponent.parseMimeComponent(in);//, MailParserTools.getBoundary(getHeaderArray()));

                // analyse results
                if (mimeparts == null)
                    throw new EmailDataFormatException("Malformed email.");
               
                // construct email
                body = mimeparts.getData();
                
                EmailHeader heads[] = mimeparts.getHeaders();
                headers = new Vector();
                for (int n = 0; n < heads.length; n++)
                    headers.add(heads[n]);
 
                MimeComponent subcomps [] = mimeparts.getSubComponents();
                if (subcomps!=null) {
                    mimeBody = new Vector();
                    attachments = new Vector();
                    
                    for (int n = 0; n<subcomps.length; n++) {
                        if (subcomps[n] instanceof EmailAttachment)
                            attachments.add(subcomps[n]);
                        else
                            mimeBody.add(subcomps[n]);
                    }
                }
        } catch (IOException e) {
            throw new EmailDataFormatException(e.getMessage());
        } 
        
    }
    
    /** 
     * <p>Construct an email in a form compatible with electronic transmission.</p>
     */
    public byte [] getBytes() throws EmailDataFormatException {
        try {
            
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            
            // construct header
            EmailHeader [] header = getHeaderArray();
            for (int n = 0; n < header.length; n++) {
                out.write(header[n].toString().getBytes());
                out.write("\r\n".getBytes());
            }

            out.write("\r\n".getBytes()); 
                 
            // construct body
            out.write(body);
            
            // output any mime components
            
                // construct full mail 
                Vector mimecomps = new Vector();
                
                    // add body components
                    if ((mimeBody!=null) && (mimeBody.size()>0))
                        mimecomps.addAll(mimeBody);
                    
                    // add attachments
                    if ((attachments!=null) && (attachments.size()>0))
                        mimecomps.addAll(attachments);
                
                // output any components
                    if (mimecomps.size()>0) {
                        String boundary = MailParserTools.getBoundary(getHeaderArray());
                        if (boundary == null)
                            throw new EmailDataFormatException("Badly formatted MIME header!");


                        out.write(new String("--"+boundary+"\r\n").getBytes()); // output first boundary

                        for (int n = 0; n < mimecomps.size(); n++) {
                            MimeComponent tmp = (MimeComponent)mimecomps.elementAt(n);
                            out.write(tmp.getBytes());

                            if (n==mimecomps.size()-1)
                                out.write(new String("--"+boundary+"--\r\n").getBytes()); // output final boundary
                            else
                                out.write(new String("--"+boundary+"\r\n").getBytes()); // output boundary
                        }
                    }
                   
            out.close();
            
            return out.toByteArray();
            
        } catch (IOException e) {
            throw new EmailDataFormatException(e.getMessage());
        }
        
    }
    
}