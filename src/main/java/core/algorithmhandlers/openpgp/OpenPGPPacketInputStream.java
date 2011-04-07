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

package core.algorithmhandlers.openpgp;
import core.algorithmhandlers.openpgp.packets.*;
import core.exceptions.AlgorithmException;
import java.io.*;

/**
 * <p>A class that can produce PGP packets out of an incoming byte stream.</p>
 * <p>Note: This class looks at the stream in a very low level way and so assumes that the stream is unicode.</p>
 */
public class OpenPGPPacketInputStream {

    /** Stream to read packet bytes from.*/
    private InputStream inputStream;

    /** Creates a new instance of IncomingPGPPacketStream.
     * @param stream The stream to read package data from.
     */
    public OpenPGPPacketInputStream(InputStream stream) {
        inputStream = stream;
    }

    /** <p>Internal function that builds a packet out of an array of bytes containing binary data.</p>
     * @throws IOException if there was a problem constructing the packet.
     */
    protected Packet buildPacket(PacketHeader header, byte data[]) throws AlgorithmException {
        
        Packet p = null;
        
        switch (header.getType()) 
        {                
            case 1  : p = new PublicKeyEncryptedSessionKeyPacket(); break; // Public-key Encrypted Session Key Packet
            case 2  : p = new SignaturePacket(); break; // Signature Packet
            case 3  : p = new SymmetricKeyEncryptedSessionKeyPacket(); break; // Symmetric-key encrypted session key packet
            case 4  : p = new OnePassSignaturePacket(); break; // one-pass signature packet
            case 5  : p = new SecretKeyPacket(); break; // Secret key packet
            case 6  : p = new PublicKeyPacket(); break; // Public key packet
            case 7  : p = new SecretSubkeyPacket(); break; // Secret Subkey packet
            case 8  : p = new CompressedDataPacket(); break; // Compressed data packet
            case 9  : p = new SymmetricallyEncryptedDataPacket(); break; // Symmetrically Encrypted data packet
            case 10 : p = new MarkerPacket(); break; // Marker packet
            case 11 : p = new LiteralDataPacket(); break; // Literal data packet
            case 12 : p = new TrustPacket(); break; // Trust packet
            case 13 : p = new UserIDPacket(); break; // User ID packet
            case 14 : p = new PublicSubkeyPacket(); break; // Public subkey packet
            case 17 : p = new UserAttributePacket(); break; // User Attribute Packet
            case 18 : p = new SymmetricallyEncryptedIntegrityProtectedDataPacket(); 
            		// Symmetrically Encrypted Integrity Protected Data Packet
            		break;
            case 19 : // MDC packets are processed on the fly from within packet type 18 -
            		// if it processed here it is misplaced, so throw exception

            default : throw new AlgorithmException("Invalid packet tag or packet type '" + 
            		header.getType() + "' not implemented."); 
        }
        
        // construct packet using low level methods. If we got this far then the packet should have been constructed correctly
        p.setPacketHeader(header);
        p.buildPacket(data);
        
        return p;
    }

    /** <p>Reads a OpenPGP Packet at the current stream position.<p>
     * <p>Will block until a packet has been compleated unless there was an error or the stream is not ready.</p>
     * @return A openPGP packet, or NULL if the end of the stream has been reached.
     * @throws IOException if there was a problem reading from the stream or the underlying stream was not ready.
     * @throws AlgorithmException if the packet was not valid.
     */
    public Packet readPacket() throws IOException, AlgorithmException {
        
        Packet packet = null;
        
        int ptag = 0;
        boolean newformat = false;
        boolean isPartial = false;
        int type = 255;
        int lengthtype = 0;
        int bodylength = 0; // may cause problems with long packets?
        
        if ((ptag = (inputStream.read() & 0xff))!=255) { // if not end of stream.
            // look at header
                // check to see if this header is valid
                if (ptag < 128) throw new AlgorithmException("Invalid PGP packet header!");

                // new or old?
                if( ptag >= 192 ) 
                    newformat = true; // must be new format header

                // type
                if (newformat) {
                    // new format header here
                    type = ptag & 0x3F;
                    lengthtype = -1;
                } else {
                    // old format header here
                    type = (ptag >> 2) & 0x0F;
                    lengthtype = ptag & 0x03;
                }

            // body length
                if (newformat) {
                    // involved header read
                    int octet1 = (inputStream.read() & 0xFF); // read first octet
                    if (octet1 < 192) { // one octet header 
                        bodylength = octet1; 
                    } else if ( (octet1 >= 192) && (octet1 < 224) ) { // two octet header
                        bodylength = ((octet1 - 192) << 8) + inputStream.read() + 192;
                    } else if (octet1 == 255) { // five octet header
                        bodylength = ( ((inputStream.read() & 0xFF) << 24) | 
                            ((inputStream.read() & 0xFF) << 16) | 
                            ((inputStream.read() & 0xFF) <<  8) |
                            ((inputStream.read() & 0xFF) ) ); 
                    } else { // partial
                        bodylength = 1 << (octet1 & 0x1f);
                        isPartial = true;
                    }

                } else {
                    // old format
                    switch (lengthtype) {
                        case 0: bodylength = (inputStream.read() & 0xFF); break;
                        case 1: bodylength = ( ((inputStream.read() & 0xFF) << 8) | (inputStream.read() & 0xFF)); break;
                        case 2: bodylength = ( ((inputStream.read() & 0xFF) << 24) | 
                            ((inputStream.read() & 0xFF) << 16) | 
                            ((inputStream.read() & 0xFF) <<  8) |
                            ((inputStream.read() & 0xFF) ) ); break;
                        case 3: bodylength = -1; break; // indeterminate. Using old style intermediate packets is not recommended practice and is unreliable. I'm not sure intermediate is ever going to be used in this application.
                        default:
                            throw new AlgorithmException("Invalid Oldstyle PGP length type in packet!");
                    }
                }

            // read rest of data 
            byte data[];
            
            if ( (!newformat) && (bodylength == -1) ) {
                // handle old style indeterminate. Read available data from the stream.
                // old style indeterminate is UNRELIABLE and should NOT be used.
                data = new byte[inputStream.available()];
            } else {
            	data = new byte[bodylength];
            }

            //byte data[] = new byte[bodylength];
            inputStream.read(data);
            
            //deal with partial body lengths.
            if (isPartial) { // we know it's a new format packet
            	debug.Debug.println(1, "Processed partial packet length, first section is " +
            			bodylength + " bytes");
            	
            	int extralength;
            	
            	while (isPartial) {
            		isPartial = false;
            		byte[] extraData;
            		
                	int octet1 = (inputStream.read() & 0xFF); // read first octet
                    if (octet1 < 192) { // one octet header 
                    	extralength = octet1; 
                    } else if ( (octet1 >= 192) && (octet1 < 224) ) { // two octet header
                    	extralength = ((octet1 - 192) << 8) + inputStream.read() + 192;
                    } else if (octet1 == 255) { // five octet header
                    	extralength = ( ((inputStream.read() & 0xFF) << 24) | 
                            ((inputStream.read() & 0xFF) << 16) | 
                            ((inputStream.read() & 0xFF) <<  8) |
                            ((inputStream.read() & 0xFF) ) ); 
                    } else { // partial
                    	extralength = 1 << (octet1 & 0x1f);
                        isPartial = true;
                    }
                    debug.Debug.println(1, "Next section is " + extralength + " bytes");
                    extraData = new byte[extralength];
                    inputStream.read(extraData);
                    byte[] allData = new byte[data.length + extraData.length];
                    System.arraycopy(data, 0, allData, 0, data.length);
                    System.arraycopy(extraData, 0, allData, data.length, extraData.length);
                    data = allData;
                    bodylength = data.length;
                    debug.Debug.println(1, "Total packet length so far is " + 
                    		bodylength + " bytes");
            	}
            }
            
            // construct packet
            packet = buildPacket(new PacketHeader(type, newformat, lengthtype, 
            		(long)bodylength & 0xFFFFFFFFL),data);
        }
    
        return packet;
    }

    /** <p>Close the stream.</p>
     * <p>Closes the stream and performs necessary cleanup. Once closed, a stream can not be reopened.</p>
     */
    public void close() throws IOException {
        inputStream.close();
    }

}
