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
import core.email.encoders.*;
import java.io.*;
import java.util.Vector;

/**
 * A class representing a MIME component.
 */
public class MimeComponent {
    
    /** Raw encoding / encoding unknown */
    public static final int RAW = 0;
    
    /** Base 64 encoding.*/
    public static final int BASE64 = 1;
    
    /** 7bit encoding.*/
    public static final int SEVENBIT = 2;
    
    /** Quoted printable encoding.*/
    public static final int QUOTEDPRINTABLE = 3;

    
    /** Component headers. */
    private Vector componentHeaders;
    
    /** Sub components. */
    private Vector subComponents;
    
    /** The component's data. */
    private byte [] data;
    
    /** Data encoding format. */
    private int encoding;
    
    
    /** Creates a new instance of MimeComponent */
    public MimeComponent() {
    }
    
    /** Creates a new instance of MimeComponent.
     * @param headers[] MIME component headers.
     * @param bodydata[] The mime body data (encoded according to headers).
     * @param subcomponents[] Any sub components
     */
    public MimeComponent(EmailHeader [] headers, byte [] bodydata, MimeComponent [] subcomponents) throws EmailDataFormatException {
        setHeaders(headers);
        setData(bodydata);
        setSubComponents(subcomponents);
    }
  
    /** Return the raw encoded data. */
    public byte[] getData() {
        return data;
    }
    
    /** Set the component's raw data with no conversion. */
    public void setData(byte data[]) {
        this.data = data;
    }
    
    /** Parse header information and extract transfer encoding etc. */
    protected void parseHeaders() {
        
        // extract encoding
        EmailHeader [] headers = getHeader("Content-Transfer-Encoding");     
        if (headers!=null) {
            if (headers[0].getTagValue().compareToIgnoreCase("7bit")==0) 
                encoding = SEVENBIT;
            else if(headers[0].getTagValue().compareToIgnoreCase("quoted-printable")==0)
                encoding = QUOTEDPRINTABLE;
            else if(headers[0].getTagValue().compareToIgnoreCase("base64")==0)
                encoding = BASE64;
            else
                encoding = RAW;
        }
    }
    
    /** Set the component headers. */
    public void setHeaders(EmailHeader [] headers){
        
        componentHeaders = new Vector();
        
        for (int n = 0; n < headers.length; n++) 
            componentHeaders.add(headers[n]);
        
        parseHeaders();
    }
    
    /** Get the component headers. */
    public EmailHeader [] getHeaders() {
        
        if ( (componentHeaders == null) || (componentHeaders.size()==0) )
            return null;
        
        EmailHeader [] tmp = new EmailHeader[componentHeaders.size()];
        for (int n = 0; n < componentHeaders.size(); n++)
            tmp[n] = (EmailHeader)componentHeaders.elementAt(n);
        
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
        
        if ((componentHeaders==null) || (getHeader(tag)==null)) {
            // tag does not already exist, add it
            if (componentHeaders == null) componentHeaders = new Vector();
            componentHeaders.add(new EmailHeader(tag, value));
        } else {
            for (int n = 0; n < componentHeaders.size(); n++) {
                EmailHeader head = (EmailHeader)componentHeaders.elementAt(n);
                if (tag.compareToIgnoreCase(head.getTagName())==0) {
                    componentHeaders.set(n, head);
                }
            }
        }
        
        parseHeaders();
    }
    
    /** 
     * <p>Return all headers matching a given tag.</p>
     * <p>Note, the search is case insensitive.</p>
     * @return The an array of all matching headers, or null if none found.
     */
    public EmailHeader [] getHeader(String tag) {
        if ((componentHeaders == null) || (componentHeaders.size()==0))
            return null;
        
        Vector subset = new Vector();
        
        // look for matching tags
        for (int n = 0; n < componentHeaders.size(); n++) {
            EmailHeader head = (EmailHeader)componentHeaders.elementAt(n);
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
    
    /** Get the mime sub components (if any) */
    public MimeComponent [] getSubComponents() {
        if ((subComponents == null) || (subComponents.size()==0))
            return null;
        
        MimeComponent tmp[] = new MimeComponent[subComponents.size()];
        for (int n = 0; n < subComponents.size(); n++) 
            tmp[n] = (MimeComponent)subComponents.elementAt(n);
        
        return tmp;
    }
    
    /** Set the sub components. */
    public void setSubComponents(MimeComponent [] components) {
        
        if (components!=null) {

            subComponents = new Vector();

            for (int n =0; n<components.length; n++) 
                addSubComponent(components[n]);
        }
    }
    
    /** Add the sub component to the end of the already existing list. */
    public void addSubComponent(MimeComponent component) {
        if (component!=null) {
            if ((subComponents==null) || (subComponents.size()==0)) 
                subComponents = new Vector();

            subComponents.add(component);
        }
    }
    
    /** Return the component in its encoded form. 
     * @throws EmailDataFormatException if there was a problem constructing the component.
     */
    public byte [] getBytes() throws EmailDataFormatException {
        
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            // output the headers
            EmailHeader [] headers = getHeaders();
            if ((headers != null) && (headers.length>0))
                for (int n = 0; n < headers.length; n++) {
                    out.write(headers[n].toString().getBytes());
                    out.write("\r\n".getBytes());
                }

            out.write("\r\n".getBytes());

            // write out component body
            if (getData()!=null) {
                out.write(getData());
                //out.write("\r\n".getBytes());
            }
            
            // write out the body of the component if there are any

            MimeComponent [] subs = getSubComponents();
            
            if ((subs != null) && (subs.length > 0)) {
                // component has sub components. Render them out

                // extract boundary              
                String boundary = MailParserTools.getBoundary(getHeaders());

                out.write(new String("--"+boundary+"\r\n").getBytes()); // output first boundary
                for (int n = 0; n < subs.length; n++) {

                    out.write(subs[n].getBytes());
                    if (n==subs.length-1)
                        out.write(new String("--"+boundary+"--\r\n").getBytes()); // output final boundary
                    else
                        out.write(new String("--"+boundary+"\r\n").getBytes()); // output boundary
                }
            } 
        
            return out.toByteArray();
        } catch (Exception e) {
            throw new EmailDataFormatException(e.getMessage());
        }

    }
    
    /** How is this attachment encoded? */
    public int getEncoding() {
        return encoding;
    }
        
    /** Decode mime body to raw binary data. */
    public byte [] decode() throws IOException {
        switch (getEncoding()) {
            case BASE64 : return Base64.decode(getData());
            case QUOTEDPRINTABLE : return QuotedPrintable.decode(getData());     
            default : return getData();
        }
    }
    
    
    
    
    
    /**
     * <p>Parse mime sub components.</p>
     * <p>This method parses out the mime component at the current stream position.</p>
     * @param in Input stream to read data from (must be placed at the beginning of the header block).
     * @param boundary The boundary stream to seach for.
     * @throws IOException if there was an IO problem.
     * @throws EmailFormatDataException if the email could not be parsed.
     * @return the constructed mime component
     */
    public static MimeComponent [] parseMimeSubComponents(InputStream in, String boundary) throws IOException, EmailDataFormatException {
        Vector subcomps = new Vector();
        
        String line = null;
        do { 
            ByteArrayOutputStream tmp = new ByteArrayOutputStream();
            
            do {
                line = IOUtil.readLine(in);
                if ( (!line.endsWith(boundary)) && (!line.endsWith(boundary+"--")) ) {
                    tmp.write(line.getBytes());
                    tmp.write("\r\n".getBytes());
                }
            } while ((in.available()>0) && (!line.endsWith(boundary)));
            
            
            ByteArrayInputStream sub = new ByteArrayInputStream(tmp.toByteArray());
            MimeComponent tmpsub = parseMimeComponent(sub);
            if (tmpsub!=null)
                subcomps.add(tmpsub);

        } while ((in.available()>0) && (!line.endsWith(boundary+"--")));
        
        
        MimeComponent [] tmp = new MimeComponent[subcomps.size()];
        for (int n = 0; n < tmp.length; n++)
            tmp[n] = (MimeComponent)subcomps.elementAt(n);
        
        return tmp;
    }
    
    /**
     * <p>Parse mime components.</p>
     * <p>This method parses out the mime component at the current stream position.</p>
     * @param in Input stream to read data from (must be placed at the beginning of the header block).
     * @throws IOException if there was an IO problem.
     * @throws EmailFormatDataException if the email could not be parsed.
     * @return the constructed mime component
     */
    public static MimeComponent parseMimeComponent(InputStream in) throws IOException, EmailDataFormatException {
        // read headers      
        EmailHeader [] heads = EmailHeader.parseHeaders(in);
        if (heads==null) // should have some headers
            throw new EmailDataFormatException("Malformed message header or no headers found");
        
        // test for attachment
        EmailHeader contentdisp = null;
        for (int n = 0; n < heads.length; n++) {
            if (heads[n].getTagName().compareToIgnoreCase("Content-Disposition")==0)
                contentdisp = heads[n];
        }
        
        MimeComponent rootnode = null;
        
        if ((contentdisp!=null) && ((contentdisp.getTagValue().toLowerCase().indexOf("attachment")!=-1) || ((contentdisp.getTagValue().toLowerCase().indexOf("inline")!=-1) && (contentdisp.getTagValue().indexOf("filename=")!=-1)))) {
            // this is an attachment (is explicitly an attachment, or inline with filename)     
            rootnode = new EmailAttachment();          
        } else {
            // this is another mime type       
            rootnode = new MimeComponent();               
            rootnode.setHeaders(heads);
        }
        
        // do the headers define a content boundary?
        String hBoundary = null;
        if (heads!=null)
            hBoundary = MailParserTools.getBoundary(heads);

        if (hBoundary!=null) {        
            // component defines a boundary, there are sub components
            ByteArrayOutputStream tmp = new ByteArrayOutputStream();
            String line = null;
            
            // read body
            line = IOUtil.readLine(in);            
            while ((in.available()>0) && (!line.endsWith(hBoundary))) {                
                tmp.write(line.getBytes()); 
                tmp.write("\r\n".getBytes());
                line = IOUtil.readLine(in);                      
            }
                
            if (rootnode instanceof EmailAttachment) {
                rootnode = new EmailAttachment(heads, tmp.toByteArray());
            } else {
                rootnode.setData(tmp.toByteArray());
            }
            
            // find sub components
            MimeComponent tmpsub [] = parseMimeSubComponents(in, hBoundary);
            if (tmpsub!=null) {
                for (int n = 0; n < tmpsub.length; n++)
                    rootnode.addSubComponent(tmpsub[n]);
            }
            
        } else {          
            // there are no sub components, the component consists of a body only         
            byte [] body = new byte[in.available()];
            in.read(body);

            if (rootnode instanceof EmailAttachment) {
                rootnode = new EmailAttachment(heads, body);
            } else {
                rootnode.setData(body);
            }
        }
        
        return rootnode;
    }
}
