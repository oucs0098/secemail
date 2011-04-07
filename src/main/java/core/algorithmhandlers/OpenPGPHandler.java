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

package core.algorithmhandlers;
import core.keyhandlers.*;
import core.keyhandlers.identifiers.*;
import core.keyhandlers.parameters.*;
import core.keyhandlers.keydata.*;
import core.exceptions.*;
import core.email.*;
import core.email.util.*;
import core.email.encoders.*;
import core.algorithmhandlers.openpgp.*;
import core.algorithmhandlers.openpgp.packets.v4signature.*;
import core.algorithmhandlers.openpgp.packets.*;
import core.algorithmhandlers.openpgp.util.*;
import java.security.*;
import java.io.*;
import java.util.*;
import org.bouncycastle.jce.provider.*;

/**
 * <p>Open PGP handler.</p>
 * <p>Implements the OpenPGP spec.</p>
 * <p>FIXME: Does not properly handle HTML/RTF emails.</p>
 * @see <a href="http://www.faqs.org/rfcs/rfc2440.html" target="_blank">The OpenPGP Spec (RFC2440)</a>
 */
public class OpenPGPHandler extends AlgorithmHandler {

    /** Symmetric algorithm */
    private int symmetricAlgorithm;


    /** <p>Creates a new instance of OpenPGPHandler.</p>
     * @param symmetricAlgorithm Default symmetric key algorithm to use if not specified in recipient's public keyring.
     */
    public OpenPGPHandler(int symmetricAlgorithm) throws AlgorithmException {
        setSymmetricAlgorithm(symmetricAlgorithm);
    }

    /** Set the symmetric key algorithm. */
    public void setSymmetricAlgorithm(int algorithm) {
        symmetricAlgorithm = algorithm;
    }

    /** Get the symmetric algorithm. */
    public int getSymmetricAlgorithm() {
        return symmetricAlgorithm;
    }


    /**
     * <p>Process an outgoing email.</p>
     * <p>This method does the main processing of an outgoing email. Its behaviour is different depending on the
     * options specified.</p>
     * @param encrypt Should the email be encrypted?
     * @param sign Should the email be signed?
     * @param publicKeyStores[] An array of available public key stores.
     * @param privateKeyStores[] An array of availabe private key stores.
     * @param email The email being processed.
     * @param passPhrases A list of passphrases to try unlocking keydata with.
     * @return A new Email object containing the processed data.
     * @throws AlgorithmException if there was an unrecoverable algorithm specific problem.
     * @throws KeyHandlerException if there was an unrecoverable key handler specific problem.
     * @throws ChecksumFailureException if the password you entered was not right.
     * @throws SecretKeyNotFoundException if a key could not be found in a secret keystore.
     * @throws PublicKeyNotFoundException if a key could not be found in a public keystore.
     * @throws EmailDataFormatException if the email was badly formatted and could not be parsed.
     */
    public Email processOutgoingMail(boolean encrypt, boolean sign, KeyHandler[] publicKeyStores, KeyHandler[] privateKeyStores, Email email, PassPhrase[] passPhrases) throws AlgorithmException, KeyHandlerException, ChecksumFailureException, SecretKeyNotFoundException, PublicKeyNotFoundException, EmailDataFormatException {

            Email newEmail = new Email(email);

            String signer = null;

            try {

                    if (sign) {
                            // Find signing key (from from header field), passphrase failure here will be handled by caller
                            EmailHeader from[] = email.getHeader("from");
                            signer = from[0].getTagValue();

                            // sign body
                            if (newEmail.getMimeBody()!=null) {
                                    // special body, need to parse

                                    newEmail.setMimeBody(signMimeBody(privateKeyStores, signer, passPhrases, newEmail.getMimeBody()));

                            } else {
                                    // normal body
                                    newEmail.setBody(signBody(privateKeyStores, signer, passPhrases, newEmail.getBody()));
                            }


                    }

                    if (encrypt) {

                            String recp[] = email.getRecipients();

                            // TODO : Use recipients algorithm preferences.

                            // encrypt body
                            if (newEmail.getMimeBody()!=null) {
                                    // MIME body, need to encrypt each sub component
                                    newEmail.setMimeBody(encryptMimeBody(publicKeyStores, recp, newEmail.getMimeBody()));

                            } else {
                                    // normal body
                                    newEmail.setBody(encryptBody(publicKeyStores, recp, newEmail.getBody()));
                            }

                            // encrypt attachments
                            if (newEmail.getAttachments()!=null) {
                                    // there are attachments

                                    EmailAttachment encryptedAttachments[] = encryptAttachments(publicKeyStores, recp, newEmail.getAttachments());

                                    // store attachments in email
                                    newEmail.purgeAttachments();
                                    for (int n=0; n<encryptedAttachments.length; n++)
                                            newEmail.addAttachment(encryptedAttachments[n]);
                            }
                    }

                    // sign attachments
                    if (sign) {

                            // sign attachments
                            EmailAttachment attachments[] = newEmail.getAttachments();
                            if (attachments!=null) {
                                    // there are attachments

                                    // sign data
                                    EmailAttachment encryptedAttachments[] = signAttachments(privateKeyStores, signer, passPhrases, newEmail.getAttachments());

                                    // store signature attachments in email
                                    for (int n=0; n<encryptedAttachments.length; n++)
                                            newEmail.addAttachment(encryptedAttachments[n]);
                            }
                    }

                    // construct message
                    return newEmail;

            } catch (IOException e) {
                    throw new AlgorithmException(e.getMessage());
            }

    }

    /**
     * <p>Process an incoming email.</p>
     * <p>This method does all the main processing of an incoming email. It will attempt to decrypt any encrypted and verify any signed
     * messages / attachments.</p>
     * <p>All non-fatal errors (signature invalid, public key not found etc) encountered while processing are written to a log.
     * This log is then written to the processed email as an attachment for convenience.</p>
     * @param publicKeyStores[] An array of available public key stores.
     * @param privateKeyStores[] An array of availabe private key stores.
     * @param email The email being processed.
     * @param passPhrases A list of passphrases to try unlocking keydata with.
     * @return A new Email object containing the processed data.
     * @throws AlgorithmException if there was an unrecoverable algorithm specific problem.
     * @throws KeyHandlerException if there was an unrecoverable key handler specific problem.
     * @throws ChecksumFailureException if the password you entered was not right.
     * @throws SecretKeyNotFoundException if a key could not be found in a secret keystore.
     * @throws PublicKeyNotFoundException if a key could not be found in a public keystore.
     * @throws EmailDataFormatException if the email was badly formatted and could not be parsed.
     */
    public Email processIncomingMail(KeyHandler[] publicKeyStores, KeyHandler[] privateKeyStores, Email email, PassPhrase[] passPhrases) throws AlgorithmException, KeyHandlerException, ChecksumFailureException, SecretKeyNotFoundException, PublicKeyNotFoundException, EmailDataFormatException {

        Email newEmail = new Email(email);

        try {
            
            OpenPGPLogger log = new OpenPGPLogger();
            log.beginSection("Processing incoming Email");
            
            // process message bodies
            if (newEmail.getMimeBody()!=null) {
                // multipart mime body
                log.beginSection("Processing multipart body"); //writeLog(log, "Processing multipart body...\r\n");

                    // first pass (decrypt & verify)
                    try {
                        newEmail.setMimeBody(processIncomingMimeMessageBody(log, publicKeyStores, privateKeyStores, passPhrases, newEmail.getMimeBody()));
                    } catch (ChecksumFailureException passfail) {
                        throw passfail; // catch password failure and rethrow.
                    } catch (Exception e) {
                        log.logError(e.getMessage());
                    }

                log.endSection(); 

            } else {
                // no mime body
                log.beginSection("Processing body"); 

                    // first pass (decrypt & verify)
                    try {
                        newEmail.setBody(decryptIncomingMessageBody(log, publicKeyStores, privateKeyStores, passPhrases, newEmail.getBody()));
                        newEmail.setBody(verifyIncomingMessageBody(log, publicKeyStores, privateKeyStores, passPhrases, newEmail.getBody()));
                    } catch (ChecksumFailureException passfail) {
                        throw passfail; // catch password failure and rethrow.
                    } catch (Exception e) {
                        log.logError(e.getMessage());
                    }

                log.endSection(); 
            }

            // process any attachments
            EmailAttachment [] attachments = newEmail.getAttachments();
            if (attachments!=null) {

                log.beginSection("Message has attachments");
 
                for (int n = 0; n < attachments.length; n++) {

                    if (!attachments[n].getFilename().endsWith(".sig")) {
                        // if not a signature

                        // log file
                        log.beginSection("Attachment: " + attachments[n].getFilename() + ", Size: " + attachments[n].getData().length + " bytes"); //writeLog(log, "+ Attachment: " + attachments[n].getFilename() + ", Size: " + attachments[n].getData().length + " bytes\r\n");

                        // hunt for corresponding signature
                        EmailAttachment signature = null;
                        for (int na = 0; na < attachments.length; na++) {
                            if (attachments[na].getFilename().compareTo(attachments[n].getFilename() + ".sig")==0) {
                                // signature found
                                signature = attachments[na];
                            }
                        }

                        // Attempt to verify signature if signature is found
                            if (signature == null) {
                                log.logWarning("Could not find a signature, file \"" + attachments[n].getFilename() + "\" can not be verified.");
                            } else {
                                log.logInfo("Signature file: " + signature.getFilename()); //writeLog(log, "Signature file: " + signature.getFilename() + "\r\n");

                                try {
                                    // attempt to verify attachment (needs to specially decode non-base64 data)
                                    if (!verify(log, publicKeyStores, (attachments[n].getEncoding()==EmailAttachment.BASE64) ? attachments[n].decode() : Armory.formatForCTSigning(attachments[n].decode()), signature.decode())) {
                                        throw new AlgorithmException("Signature \"" + signature.getFilename() + "\" is INVALID.");
                                    } else {
                                        log.logInfo("Signature is valid.");
                                    }

                                // catch and write errors to a log, we don't want to stop processing if something could not be verified.
                                } catch (Exception e) {
                                    log.logError(e.getMessage());
                                }
                            }

                        // if attachment is a pgp file, try and decode
                        if (attachments[n].getFilename().endsWith(".pgp")) {

                            try {

                                // process packet
                                LiteralDataPacket [] packets = decryptPgpData(privateKeyStores, passPhrases, attachments[n].decode());

                                if (packets!=null) {
                                    // remove the attachment that has now been decoded.
                                    newEmail.removeAttachment(attachments[n].getFilename());

                                    // add all descovered literal packets to email
                                    for (int na = 0; na < packets.length; na++) {

                                        // construct headers
                                        EmailHeader headers [] = new EmailHeader[3];
                                        headers[0] = new EmailHeader("Content-Type","application/octet-stream;\r\n\tname=\""+ packets[na].getFilename() +"\"");
                                        headers[1] = new EmailHeader("Content-Transfer-Encoding","base64");
                                        headers[2] = new EmailHeader("Content-Disposition","attachment;\r\n\tfilename=\""+ packets[na].getFilename() +"\"");

                                        // add attachment
                                        newEmail.addAttachment(new EmailAttachment(headers, Base64.encode(packets[na].getData())));
                                    }
                                } else {
                                    throw new AlgorithmException("No encrypted data found in file \"" + attachments[n].getFilename() + "\".");
                                }

                                // if we got here then the message should have been decrypted
                                log.logInfo("Attachment successfully decrypted.");

                            } catch (ChecksumFailureException passfail) {
                                throw passfail; // catch password failure and rethrow.
                            } catch (Exception e) {
                                log.logError(e.getMessage());
                            }
                        }
                        log.endSection(); //writeLog(log, "\r\n");
                    }
                }

                log.endSection(); //writeLog(log, "****************************************************************************\r\n");
            }

            log.endSection(); // end mail processing
          
            // Write log to email

            // calculate the name of the log file
            String logfile = new String("SecureEmailProxy-"+log.getCreateDate().getTime()+".log");

            // write summary message

                // add summary to message
                if (newEmail.getMimeBody()!=null) {
                    // multipart mime body
                    newEmail.setMimeBody(addTextToMimeComponent(new String(log.getSummary()), newEmail.getMimeBody()));
                } else {
                    // no mime body
                    String body = new String(log.getSummary());
                    body += new String(newEmail.getBody());
                    
                    newEmail.setBody(body.getBytes());
                }

            // create log attachment

                // test to see if there are already attachments in the email, if not then we must modify the header and body information
                if (newEmail.getAttachments() == null) {

                    // no attachments, need to convert message to multipart/mixed format

                    // extract content type and boundary (if it exists)
                    EmailHeader [] oldheaders = newEmail.getHeader("Content-Type");
                    EmailHeader [] newheaders = null;

                    // construct new mime body which contains existing body
                    if (oldheaders!=null) {
                        // a content type is specified for body 
                        newheaders = new EmailHeader[oldheaders.length];
                        for (int n = 0; n < newheaders.length; n++)
                            newheaders [n] = new EmailHeader(oldheaders[n].getTagName(), oldheaders[n].getTagValue());
                    } else {
                        // no content type specified (old or naughty client), so assume text/plain 7bit encoding
                        newheaders = new EmailHeader[2];
                        newheaders[0] = new EmailHeader("Content-Type", "text/plain;\r\n\tcharset=\"iso-8859-1\"");
                        newheaders[1] = new EmailHeader("Content-Transfer-Encoding","7bit");
                    }

                    MimeComponent [] newbody = new MimeComponent[1];
                    if (newEmail.getMimeBody()!=null)
                        newbody[0] = new MimeComponent(newheaders, null, newEmail.getMimeBody()); // already mime components
                    else
                        newbody[0] = new MimeComponent(newheaders, newEmail.getBody(), null);

                    newEmail.setMimeBody(newbody);

                    // rebuild main content type header
                    newEmail.setHeader("Content-Type", "multipart/mixed;\r\n\tboundary=\"----=_SecEmail_NextPart_"+new Date().getTime()+"\"");

                    // finally, write a message for non-mime clients
                    newEmail.setBody("This is a multi-part message in MIME format.\r\n\r\n".getBytes());
                }

                EmailHeader logheaders [] = new EmailHeader[3];
                logheaders[0] = new EmailHeader("Content-Type","application/octet-stream;\r\n\tname=\""+logfile+"\"");
                logheaders[1] = new EmailHeader("Content-Transfer-Encoding","base64");
                logheaders[2] = new EmailHeader("Content-Disposition","attachment;\r\n\tfilename=\""+logfile+"\"");
                newEmail.addAttachment(new EmailAttachment(logheaders, Base64.encode(log.getLog())));
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
        
        return newEmail;
    }


/* Incoming email ***********************************************************************/

    /**
     * <p>Recursively process a mime message body.</p>
     */
    private MimeComponent [] processIncomingMimeMessageBody(OpenPGPLogger log, KeyHandler [] publicKeyStores, KeyHandler [] privateKeyStores, PassPhrase[] passPhrases, MimeComponent [] data)
        throws AlgorithmException, KeyHandlerException, ChecksumFailureException, KeyNotFoundException, EmailDataFormatException, IOException {

            MimeComponent dec[] = data;

            for (int n = 0; n < data.length; n++) {
                MimeComponent subs [] = data[n].getSubComponents();
                if (subs!=null) {
                    subs = processIncomingMimeMessageBody(log, publicKeyStores, privateKeyStores, passPhrases, subs);
                    dec[n].setSubComponents(subs);
                } else {
                    dec[n].setData(decryptIncomingMessageBody(log, publicKeyStores, privateKeyStores, passPhrases, data[n].getData()));
                    dec[n].setData(verifyIncomingMessageBody(log, publicKeyStores, privateKeyStores, passPhrases, dec[n].getData()));
                }

            }
            
            return dec;
    }
    
    /**
     * <p>Parse a message body and decrypt the contents of the message.</p>
     * <p>Returns an array of the result or an unaltered array if something went wrong or no encrypted message was found.</p>
     * <p>Progress is written to the email and the log file.</p>
     */
    private byte [] decryptIncomingMessageBody(OpenPGPLogger log, KeyHandler [] publicKeyStores, KeyHandler [] privateKeyStores, PassPhrase [] passphrases, byte [] data) 
        throws AlgorithmException, KeyHandlerException, ChecksumFailureException, KeyNotFoundException, EmailDataFormatException, IOException {
    
            ByteArrayInputStream in = new ByteArrayInputStream(data);
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            boolean encrypted = false;
            
            // process entire message
            String line = null;//IOUtil.readLine(in);
            do {

                line = IOUtil.readLine(in);

                // is this the begining of an encrypted message?
                if (line.compareTo("-----BEGIN PGP MESSAGE-----")==0) {
                    encrypted = true;      
                    log.logInfo("Message body is encrypted"); //writeLog(log, "Message body is encrypted.\r\n");

                    ByteArrayOutputStream tmp = new ByteArrayOutputStream();

                    // read until blank line
                    line = IOUtil.readLine(in);
                    while ((in.available()>0) && (line.length()>0))
                        line = IOUtil.readLine(in);

                    // read until end of encrypted message
                    line = IOUtil.readLine(in);
                    while ((in.available()>0) && (line.compareTo("-----END PGP MESSAGE-----")!=0)) {
                        tmp.write(line.getBytes()); tmp.write("\r\n".getBytes());

                        line = IOUtil.readLine(in);
                    }

                    if (line.compareTo("-----END PGP MESSAGE-----")==0) {
                        LiteralDataPacket [] d = decryptPgpData(privateKeyStores, passphrases, Armory.disarm(new String(tmp.toByteArray())));
                        if (d!=null) {
                            for (int n = 0; n < d.length; n++) {
                                out.write(d[n].getData());
                                out.write("\r\n".getBytes());
                            }
                        } else {
                            throw new AlgorithmException("No encrypted data found in file.");
                        }
                    } else {
                        throw new AlgorithmException("Encrypted message is incomplete.");
                    }

                } else {
                    out.write(line.getBytes()); out.write("\r\n".getBytes());
                }

            } while (in.available()>0);
            
            // display a message if the message was not encrypted
            if (!encrypted)
                log.logWarning("Message was not encrypted.");

            return out.toByteArray();
    }
    
    /**
     * <p>Parse a message body and verify the contents of the message.</p>
     * <p>Returns an array of the result or an unaltered array if something went wrong or no signed message was found.</p>
     * <p>Progress is written to the email and the log file.</p>
     */
    private byte [] verifyIncomingMessageBody(OpenPGPLogger log, KeyHandler [] publicKeyStores, KeyHandler [] privateKeyStores, PassPhrase [] passphrases, byte [] data) 
        throws AlgorithmException, KeyHandlerException, ChecksumFailureException, KeyNotFoundException, EmailDataFormatException, IOException {
            
            ByteArrayInputStream in = new ByteArrayInputStream(data);
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            boolean signed = false;
            
            // process entire message
            String line = null;
            do {

                line = IOUtil.readLine(in);

                // is this the beginning of a signed message
                if (line.compareTo("-----BEGIN PGP SIGNED MESSAGE-----")==0) {

                    signed = true;
                    
                    out.write("***** BEGINNING PGP SIGNED MESSAGE *****\r\n".getBytes());
                    log.logInfo("Message body is signed"); //writeLog(log, "Message body is signed.\r\n");

                    ByteArrayOutputStream tmp = new ByteArrayOutputStream();

                    // read until blank line
                    line = IOUtil.readLine(in);
                    out.write(line.getBytes()); out.write("\r\n".getBytes());
                    while ((in.available()>0) && (line.length()>0)) {
                        line = IOUtil.readLine(in);
                        out.write(line.getBytes()); out.write("\r\n".getBytes());
                    }

                    // read until end of signed message
                    line = IOUtil.readLine(in);
                    while ((in.available()>0) && (line.compareTo("-----BEGIN PGP SIGNATURE-----")!=0)) {
                        tmp.write(line.getBytes()); tmp.write("\r\n".getBytes());

                        line = IOUtil.readLine(in);
                    }
                    out.write(tmp.toByteArray());

                    if (line.compareTo("-----BEGIN PGP SIGNATURE-----")==0) {
                        // read until end signature

                        out.write("***** BEGINNING PGP SIGNATURE *****\r\n".getBytes());

                        ByteArrayOutputStream tmp2 = new ByteArrayOutputStream();

                        // read until blank line
                        line = IOUtil.readLine(in);
                        while ((in.available()>0) && (line.length()>0)) {
                            line = IOUtil.readLine(in);
                        }

                        // read signature
                        line = IOUtil.readLine(in);
                        while ((in.available()>0) && (line.compareTo("-----END PGP SIGNATURE-----")!=0)) {
                            tmp2.write(line.getBytes()); tmp2.write("\r\n".getBytes());
                            line = IOUtil.readLine(in);
                        }

                        // verify signature
                        if (line.compareTo("-----END PGP SIGNATURE-----")==0) {
                            //if (!verify(log, publicKeyStores, Armory.removeDashEscaping(new String(tmp.toByteArray())).getBytes(), Armory.disarm(new String(tmp2.toByteArray())))) {
                            if (!verify(log, publicKeyStores, Armory.formatForCTSigning(Armory.removeDashEscaping(new String(tmp.toByteArray())).getBytes()), Armory.disarm(new String(tmp2.toByteArray())))) {
                                throw new AlgorithmException("Signature is INVALID.");
                            } else {
                                log.logInfo("Signature is valid"); 

                                out.write("Signature is VALID.\r\n".getBytes());
                                out.write("***** END OF PGP SIGNED MESSAGE *****\r\n".getBytes());
                            }
                        } else {
                            throw new AlgorithmException("Signed message is incomplete.");
                        }


                    } else {
                        throw new AlgorithmException("Signed message is incomplete.");
                    }

                // normal body line, write it out.
                } else {
                    out.write(line.getBytes()); out.write("\r\n".getBytes());
                }

            } while (in.available()>0);
            
            // Display a message if a message body is not signed
            if (!signed)
                log.logWarning("No signature found, message body can not be verified.");

            return out.toByteArray();
    }

/****************************************************************************************/

/* Signature methods ********************************************************************/

    /**
     * <p>Verify a given signature.</p>
     * <p>Returns true if successfully verified, false if not. Key ID is written in the log file.</p>
     */
    private boolean verify(OpenPGPLogger log, KeyHandler[] publicKeyStores, byte [] data, byte [] signature)
        throws AlgorithmException, KeyHandlerException, ChecksumFailureException, KeyNotFoundException, EmailDataFormatException, IOException {

            OpenPGPPacketInputStream pin = new OpenPGPPacketInputStream(new ByteArrayInputStream(signature));

            // decode packet
            Packet p = pin.readPacket();
            SignaturePacket sig = null;
            if (p instanceof SignaturePacket) {

				// Extract signature key ID and write it to the log
                sig = (SignaturePacket)p;
                byte [] keyid = sig.getKeyID();

                String keyidmessage = "Signing key ID: 0x";
                for (int n = 0; n < keyid.length; n++) {
                    if (keyid[n]<16) keyidmessage += "0"; // write preceeding 0 if necessary
                    keyidmessage += Integer.toHexString(keyid[n] & 0xFF).toUpperCase();
                }
                log.logInfo(keyidmessage);


            } else {
                throw new AlgorithmException("Warning: Signature is invalid.");
            }

            // find key
            KeyObject[] key = findKeys(publicKeyStores, new OpenPGPKeyIDKeyIdentifier(sig.getKeyID()));
            if (key==null)
                throw new PublicKeyNotFoundException("Could not find signer's public key, message can not be verified.");

            // verify
            if (sig.verify(key[0].getKeyData().getKey().getPublicKey(), data))
                return true;

            return false;

    }

	/**
	 * <p>Sign email attachments and return an array containing the corresponding .sig files.</p>
         * <p>As with the message body, if the attachment is not base64 encoded trailing whitespace and the last enter is stripped.</p>
	 */
    private EmailAttachment [] signAttachments(KeyHandler[] secretKeyStores, String signer, PassPhrase[] passPhrases, EmailAttachment [] attachments)
        throws AlgorithmException, KeyHandlerException, ChecksumFailureException, KeyNotFoundException, EmailDataFormatException, IOException {

            Vector signedAttachments = new Vector();

            // for each attachment
            for (int n = 0; n < attachments.length; n++) {

                ByteArrayOutputStream out = new ByteArrayOutputStream();
                OpenPGPPacketOutputStream pOut = new OpenPGPPacketOutputStream(out);

                // fetch key
                KeyObject[] keys = findSecretKeys(secretKeyStores, new OpenPGPStandardKeyIdentifier(signer), passPhrases);

                if (keys!=null) {
                    if (!(keys[0] instanceof OpenPGPKeyData)) throw new KeyHandlerException("The key data found for " + signer + " is of the wrong type");
                    OpenPGPKeyData signerKey = (OpenPGPKeyData)keys[0]; // the first key MUST be the signing key according to spec

                    // generate & write pk packet
                    pOut.writePacket(new SignaturePacket( new V4SignatureMaterial(
                        signerKey.getKey().getPrivateKey(),
                        0,
                        signerKey.getKeyID(),
                        (attachments[n].getEncoding()==EmailAttachment.BASE64) ? 0x00 : 0x01,
                        signerKey.getKeyPacket().getAlgorithm(),
                        HashAlgorithmSettings.SHA1,
                        (attachments[n].getEncoding()==EmailAttachment.BASE64) ? attachments[n].decode() : Armory.formatForCTSigning(attachments[n].decode())
                    )));

                    pOut.close();

                    EmailHeader [] signedattachheaders = new EmailHeader[3];
                    signedattachheaders[0] = new EmailHeader("Content-Type","application/octet-stream;\r\n\tname=\""+attachments[n].getFilename() + ".sig"+"\"");
                    signedattachheaders[1] = new EmailHeader("Content-Transfer-Encoding","base64");
                    signedattachheaders[2] = new EmailHeader("Content-Disposition","attachment;\r\n\tfilename=\""+attachments[n].getFilename() + ".sig"+"\"");
                    signedAttachments.add(new EmailAttachment(signedattachheaders, Base64.encode(out.toByteArray())));
                } else {
                    // no key found
                    throw new SecretKeyNotFoundException("Could not find signing key for : \n   '"+signer+"'");
                }
            }

            // return attachments
            EmailAttachment [] tmp = new EmailAttachment[signedAttachments.size()];
            for (int n = 0; n < tmp.length; n++)
                tmp[n] = (EmailAttachment)signedAttachments.elementAt(n);

            return tmp;
    }

    /**
     * <p>Recursively sign and ascii armor a mime body.</p>
     */
    private MimeComponent [] signMimeBody(KeyHandler[] secretKeyStores, String signer, PassPhrase[] passPhrases, MimeComponent [] data)
	        throws AlgorithmException, KeyHandlerException, ChecksumFailureException, KeyNotFoundException, EmailDataFormatException, IOException {

	            MimeComponent enc[] = data;

	            for (int n = 0; n < data.length; n++) {
	                MimeComponent subs [] = data[n].getSubComponents();
	                if (subs!=null) {
	                    subs = signMimeBody(secretKeyStores, signer, passPhrases, subs);
	                    enc[n].setSubComponents(subs);
	                } else {
	                    enc[n].setData(signBody(secretKeyStores, signer, passPhrases, data[n].getData()));
	                }

	            }

	            return enc;
    }

	/**
	 * <p>Sign a message body</p>
	 * <p>FIXME: Does not properly handle HTML/RTF emails.</p>
	 */
    private byte [] signBody(KeyHandler[] secretKeyStores, String signer, PassPhrase[] passPhrases, byte [] data)
        throws AlgorithmException, KeyHandlerException, ChecksumFailureException, KeyNotFoundException, EmailDataFormatException, IOException {

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            OpenPGPPacketOutputStream pOut = new OpenPGPPacketOutputStream(out);

            // fetch key
            KeyObject[] keys = findSecretKeys(secretKeyStores, new OpenPGPStandardKeyIdentifier(signer), passPhrases);

            if (keys!=null) {
                if (!(keys[0] instanceof OpenPGPKeyData)) throw new KeyHandlerException("The key data found for " + signer + " is of the wrong type");
                OpenPGPKeyData signerKey = (OpenPGPKeyData)keys[0]; // the first key MUST be the signing key according to spec

                // generate & write pk packet
                pOut.writePacket(new SignaturePacket( new V4SignatureMaterial(
                    signerKey.getKey().getPrivateKey(),
                    0,
                    signerKey.getKeyID(),
                    0x01,
                    signerKey.getKeyPacket().getAlgorithm(),
                    HashAlgorithmSettings.SHA1,
                    Armory.formatForCTSigning(data)//data
                )));

                pOut.close();

                // write signed body

                // ascii armor message
                String ascii = Armory.armor(out.toByteArray());

                // construct ascii armored message
                ByteArrayOutputStream out2 = new ByteArrayOutputStream();

                out2.write("-----BEGIN PGP SIGNED MESSAGE-----\r\n".getBytes());
                out2.write("Hash: SHA1\r\n".getBytes());
                out2.write("\r\n".getBytes());
                out2.write(Armory.dashEscapeText(new String(data)).getBytes());
                out2.write("-----BEGIN PGP SIGNATURE-----\r\n".getBytes());
                out2.write("Version: Secure Email Proxy v".getBytes()); out2.write(core.CoreVersionInfo.version.getBytes()); out2.write("\r\n".getBytes());
                out2.write("Comment: Oxford Brookes Secure Email Project (".getBytes()); out2.write(core.CoreVersionInfo.website.getBytes()); out2.write(")\r\n".getBytes());
                out2.write("\r\n".getBytes());
                out2.write(ascii.getBytes());
                out2.write("-----END PGP SIGNATURE-----\r\n".getBytes());

                out2.close();

                return out2.toByteArray();

            } else {
                // no key found
                throw new SecretKeyNotFoundException("Could not find signing key for : \n   '"+signer+"'");
            }

    }

/****************************************************************************************/



/* Encryption methods *******************************************************************/

    /**
     * <p>Decrypt encrypted data and return an array of unencrypted literal data packets.</p>
     */
    private LiteralDataPacket [] decryptPgpData(KeyHandler [] privateKeyStores, PassPhrase [] passphrases, byte [] data)
        throws AlgorithmException, KeyHandlerException, ChecksumFailureException, KeyNotFoundException, EmailDataFormatException, IOException {

            Vector founddata = new Vector();

            // load any data & session key packets from
            Vector datapackets = new Vector();
            Vector publicsessionkeys = new Vector();

            OpenPGPPacketInputStream in = new OpenPGPPacketInputStream(new ByteArrayInputStream(data));

            Packet p = in.readPacket();
            while (p != null) {

                if (p instanceof EncryptedDataPacket)
                    datapackets.add(p);
                if (p instanceof PublicKeyEncryptedSessionKeyPacket)
                    publicsessionkeys.add(p);

                p = in.readPacket();
            }

            // do some validation
            if (datapackets.size() == 0)
                throw new AlgorithmException("Could not find any encrypted data.");
            if (publicsessionkeys.size() == 0)
                throw new AlgorithmException("No session keys found in PGP file, can not decrypt.");

            // look through session keys, try and find one we have a secret key for.
            for (int n = 0; n < datapackets.size(); n++) {

                boolean decoded = false; // flag so we don't attempt to decode the same message twice

                for (int na = 0; na < publicsessionkeys.size(); na++) {
                    if (!decoded) { // if not already decoded then try and decode
                        PublicKeyEncryptedSessionKeyPacket pkeskp = (PublicKeyEncryptedSessionKeyPacket)publicsessionkeys.elementAt(na);

                        KeyObject[] keys = findSecretKeys(privateKeyStores, new OpenPGPKeyIDKeyIdentifier(pkeskp.getKeyID()), passphrases);

                        if (keys == null) { // if we have tried all possible session keys and still haven't found a key that decodes this packet then throw a hissy fit
                            if (na == publicsessionkeys.size()-1)
                                throw new SecretKeyNotFoundException("No secret key could be found to decrypt this message.");
                        } else {
                            // keys found

                            // try to decrypt session key with all keys available
                            for (int cnt = 0; cnt < keys.length; cnt++) {

                                try {
                                    // try decode session key
                                    SessionKey sk = pkeskp.getSessionKey(keys[cnt].getKeyData().getKey().getPrivateKey());
                                    EncryptedDataPacket dp = null;

                                    // attempt to decode symmetric data packet with resultant session key (may fail if wrong session key used)
                                    //TODO: could be a symmetrically encrypted integrity protected packet here
                                    try {
                                        dp = (EncryptedDataPacket)datapackets.elementAt(n);
                                        dp.decryptAndDecode(sk);
                                    } catch (AlgorithmException e) {
                                        // problem decoding the message, most likely because the session key is invalid. Rethrow more friendly exception.
                                        throw new AlgorithmException("Session key is invalid, this message can not be decrypted.");
                                    }

                                    // everything has apparently decrypted ok, now do the extraction.
                                    LiteralDataPacket [] ldp = unpackPacket(dp);
                                    for (int cnt2 = 0; cnt2 < ldp.length; cnt2++)
                                        founddata.add(ldp[cnt2]);

                                    decoded = true; // set flag so we don't attempt to decode the same message twice

                                } catch (ChecksumFailureException c) {
                                    // if we have tried all keys on session key packet and it still doesn't decode then abort
                                    if (cnt == keys.length-1)
                                        throw new AlgorithmException("Session key could not be extracted, message can not be decrypted.");
                                }
                            }
                        }
                    }
                }
            }

            // return array of found data packets.
            if (founddata.size()>0) {
                LiteralDataPacket ldp[] = new LiteralDataPacket[founddata.size()];
                for (int n = 0; n < founddata.size(); n++)
                    ldp[n] = (LiteralDataPacket)founddata.elementAt(n);

                return ldp;
            }

            return null;
    }

	/**
	 * <p>Encrypt attachments and return an array of encrypted EmailAttachment. </p>
	 */
    private EmailAttachment [] encryptAttachments(KeyHandler[] publicKeyStores, String [] recp, EmailAttachment [] attachments)
        throws AlgorithmException, KeyHandlerException, ChecksumFailureException, KeyNotFoundException, EmailDataFormatException, IOException {

        EmailAttachment [] encryptedAttachments = new EmailAttachment[attachments.length];

        // for each attachment
        for (int n = 0; n < attachments.length; n++) {

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            OpenPGPPacketOutputStream pOut = new OpenPGPPacketOutputStream(out);

            // generate session key
            SessionKey sk = new SessionKey(getSymmetricAlgorithm());

            // for each recipient generate a Public key encrypted session key packet
            for (int na = 0; na < recp.length; na++) {

                // fetch key
                KeyObject[] keys = findKeys(publicKeyStores, new OpenPGPStandardKeyIdentifier(recp[na]));

                if (keys != null) { // if we have a key

                    OpenPGPKeyData encryptionKey = null;

                    // find encryption key (todo: make more reliable?)
                    if (keys.length==1) {
                        if (!(keys[0] instanceof OpenPGPKeyData)) throw new KeyHandlerException("The key data found for " + recp[na] + " is of the wrong type");
                        encryptionKey = (OpenPGPKeyData)keys[0]; // only one key, must be an encryption key
                    }
                    if (keys.length > 1) {
                        if (!(keys[1] instanceof OpenPGPKeyData)) throw new KeyHandlerException("The key data found for " + recp[na] + " is of the wrong type");
                        encryptionKey = (OpenPGPKeyData)keys[1]; // more than one key, first key is for signing, second for encryption.
                    }

                    // generate & write pk packet
                    pOut.writePacket(new PublicKeyEncryptedSessionKeyPacket(encryptionKey.getKey().getPublicKey(), encryptionKey.getKeyID(), encryptionKey.getAlgorithm(), sk));

                } else {
                    // no key found
                    throw new PublicKeyNotFoundException("Could not find public key for : \n   '"+recp[na]+"'");
                }
            }

            // generate encrypted packet
            CompressedDataPacket cp = new CompressedDataPacket(CompressedDataPacket.ZIP);
            cp.add(new LiteralDataPacket((byte)'b', attachments[n].getFilename(), attachments[n].decode()));

            SymmetricallyEncryptedDataPacket dp = new SymmetricallyEncryptedDataPacket();
            dp.add(cp);
            dp.encryptAndEncode(sk);

            pOut.writePacket(dp);
            pOut.close();

            // save attachment
            EmailHeader [] headers = new EmailHeader[3];
            headers[0] = new EmailHeader("Content-Type","application/octet-stream;\r\n\tname=\""+attachments[n].getFilename() + ".pgp"+"\"");
            headers[1] = new EmailHeader("Content-Transfer-Encoding","base64");
            headers[2] = new EmailHeader("Content-Disposition","attachment;\r\n\tfilename=\""+attachments[n].getFilename() + ".pgp"+"\"");
            encryptedAttachments[n] = new EmailAttachment(headers, Base64.encode(out.toByteArray()));
        }

        return encryptedAttachments;
    }

	/**
	 * <p>Recursively encrypt and ascii armor a mime message body.</p>
	 */
    private MimeComponent [] encryptMimeBody(KeyHandler[] publicKeyStores, String [] recp, MimeComponent [] data)
        throws AlgorithmException, KeyHandlerException, ChecksumFailureException, KeyNotFoundException, EmailDataFormatException, IOException {

            MimeComponent enc[] = data;

            for (int n = 0; n < data.length; n++) {
                MimeComponent subs [] = data[n].getSubComponents();
                if (subs!=null) {
                    subs = encryptMimeBody(publicKeyStores, recp, subs);
                    enc[n].setSubComponents(subs);
                } else {
                    enc[n].setData(encryptBody(publicKeyStores, recp, data[n].getData()));
                }

            }

            return enc;
    }

	/**
	 * <p>Encrypt and ascii armor the given message.</p>
	 * <p>FIXME: Does not properly handle HTML/RTF emails.</p>
	 */
    private byte [] encryptBody(KeyHandler[] publicKeyStores, String [] recp, byte [] data)
        throws AlgorithmException, KeyHandlerException, ChecksumFailureException, KeyNotFoundException, EmailDataFormatException, IOException {

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            OpenPGPPacketOutputStream pOut = new OpenPGPPacketOutputStream(out);

            // generate session key
            SessionKey sk = new SessionKey(getSymmetricAlgorithm());

            // for each recipient generate a Public key encrypted session key packet
            for (int na = 0; na < recp.length; na++) {

                // fetch key
                KeyObject[] keys = findKeys(publicKeyStores, new OpenPGPStandardKeyIdentifier(recp[na]));

                if (keys != null) { // if we have a key

                    OpenPGPKeyData encryptionKey = null;

                    // find encryption key (todo: make more reliable?)
                    if (keys.length==1) {
                        if (!(keys[0] instanceof OpenPGPKeyData)) throw new KeyHandlerException("The key data found for " + recp[na] + " is of the wrong type");
                        encryptionKey = (OpenPGPKeyData)keys[0]; // only one key, must be an encryption key
                    }
                    if (keys.length > 1) {
                        if (!(keys[1] instanceof OpenPGPKeyData)) throw new KeyHandlerException("The key data found for " + recp[na] + " is of the wrong type");
                        encryptionKey = (OpenPGPKeyData)keys[1]; // more than one key, first key is for signing, second for encryption.
                    }

                    // generate & write pk packet
                    pOut.writePacket(new PublicKeyEncryptedSessionKeyPacket(encryptionKey.getKey().getPublicKey(), encryptionKey.getKeyID(), encryptionKey.getAlgorithm(), sk));

                } else {
                    // no key found
                    throw new PublicKeyNotFoundException("Could not find public key for : \n   '"+recp[na]+"'");
                }
            }

            // generate encrypted packet
            CompressedDataPacket cp = new CompressedDataPacket(CompressedDataPacket.ZIP);
            cp.add(new LiteralDataPacket((byte)'b', "_CONSOLE", data));

            SymmetricallyEncryptedDataPacket dp = new SymmetricallyEncryptedDataPacket();
            dp.add(cp);
            dp.encryptAndEncode(sk);

            pOut.writePacket(dp);
            pOut.close();

            // ascii armor message
            String ascii = Armory.armor(out.toByteArray());

            // construct ascii armored message
            ByteArrayOutputStream out2 = new ByteArrayOutputStream();

            out2.write("-----BEGIN PGP MESSAGE-----\r\n".getBytes());
            out2.write("Version: Secure Email Proxy v".getBytes()); out2.write(core.CoreVersionInfo.version.getBytes()); out2.write("\r\n".getBytes());
            out2.write("Comment: Oxford Brookes Secure Email Project (".getBytes()); out2.write(core.CoreVersionInfo.website.getBytes()); out2.write(")\r\n".getBytes());
            out2.write("\r\n".getBytes());
            out2.write(ascii.getBytes());
            out2.write("-----END PGP MESSAGE-----\r\n".getBytes());

            out2.close();

            return out2.toByteArray();
    }

/****************************************************************************************/



/* Key Search ***************************************************************************/

        /** 
         * <p>Search through all key stores and attempt to locate a key.</p>
         * @return key(s) if found or null if not.
         * @throws ChecksumFailureException if a key was found but a passphrase was needed to decode the key store.
         */
	private KeyObject[] findKeys(KeyHandler[] keystore, KeyIdentifier id) throws ChecksumFailureException, KeyHandlerException {
	        for (int n = 0; n < keystore.length; n++) {
	            
                    try {
                        KeyObject[] keys = keystore[n].findKeys(id, null);

                        if (keys != null)
                            return keys;
                        
                    } catch (Exception e) {
                        // something went wrong while looking for the key. We will try other key stores if there are any left, or we'll return that
                        // we couldn't find the key
                        if (n == keystore.length-1)
                            return null;
                    }

	        }

	        return null;
        }

        /** 
         * <p>Search through all key stores and attempt to locate a key.</p>
         * @return key(s) if found or null if not.
         * @throws ChecksumFailureException if a key was found but a passphrase was needed to decode the key store.
         */
	private KeyObject[] findSecretKeys(KeyHandler[] keystore, KeyIdentifier id, PassPhrase [] passPhrases) throws KeyHandlerException, ChecksumFailureException {

	        // if passphrase list is empty then have a look to see if the key is even present. Report an error if key is not found.
	        if (passPhrases == null) {
	            for (int n = 0; n < keystore.length; n++) {

	                try {

	                    keystore[n].findKeys(id, new OpenPGPFindKeyParameters(" ".getBytes()));

	                } catch (ChecksumFailureException passfail) {
	                    // catch and rethrow password fail so that the prompt dialog displays the correct info
	                    throw passfail;
	                }  catch (Exception e) {
                            // something went wrong while looking for the key. We will try other key stores if there are any left, or we'll return that
                            // we couldn't find the key
                            if (n == keystore.length-1)
                                return null;
                        }
	            }
	        } else {

	            for (int n = 0; n < keystore.length; n++) {

                        for (int na = 0; na < passPhrases.length; na++) {
                            try {

                                KeyObject[] keys = keystore[n].findKeys(id, new OpenPGPFindKeyParameters(passPhrases[na].getPassphraseData()));

                                if (keys != null)
                                    return keys;

                            } catch (ChecksumFailureException passfail) {
                                // if the last passphrase failed then we don't have a passphrase capable of unlocking the key. Therefore elevate this.
                                if (na==passPhrases.length-1) {
                                    throw passfail;
                                }
                            } catch (Exception e) {
                                // something went wrong while looking for the key. We will try other key stores if there are any left, or we'll return that
                                // we couldn't find the key
                                if (n == keystore.length-1)
                                    return null;
                            }
                            
                        }

	            }
	        }

	        return null;
    }

/****************************************************************************************/



/* General utility methods **************************************************************/

    /**
     * <p>Recursively unpack a PGP container packet until only literal data packets remain.</p>
     * <p>Encrypted packets must have already been decrypted.</p>
     * @return An array of LiteralDataPacket.
     */
    private LiteralDataPacket [] unpackPacket(ContainerPacket p) throws AlgorithmException {
        Vector literals = new Vector();

        for (int n = 0; n<p.getNumberPacked(); n++) {
            if (p.unpack(n) instanceof ContainerPacket) {
                LiteralDataPacket [] subs = unpackPacket((ContainerPacket)p.unpack(n));
                for (int na = 0; na < subs.length; na++)
                    literals.add(subs[na]);
            } else if (p.unpack(n) instanceof LiteralDataPacket)
                literals.add(p.unpack(n));
        }

        if (literals.size() > 0) {
            LiteralDataPacket [] tmp = new LiteralDataPacket[literals.size()];
            for (int n = 0; n < tmp.length; n++)
                tmp[n] = (LiteralDataPacket)literals.elementAt(n);
            return tmp;
        }

        return null;
    }

	/**
	 * <p>Recursively add given text to all mime body components.</p>
	 * <p>This is used to write summary to the beginning of the email.</p>
	 * <p>FIXME: Does not properly handle HTML / Quoted printable.</p>
	 */
    private MimeComponent [] addTextToMimeComponent(String text, MimeComponent [] components) {

        MimeComponent data[] = components;

        for (int n = 0; n < data.length; n++) {
            MimeComponent subs [] = components[n].getSubComponents();
            if (subs!=null) {
                subs = addTextToMimeComponent(text, subs);
                data[n].setSubComponents(subs);
            } else {
                String tmp = text + new String(components[n].getData());
                data[n].setData(tmp.getBytes());
            }
        }

        return data;
    }

	

/****************************************************************************************/

    /**
     * <p>A utility class for constructing the incoming email log and summary attached to 
     * the incoming email.</p>
     */
    protected class OpenPGPLogger {
        
        /** Internal log entry. */
        protected class OpenPGPLoggerEntry {
            
            // list of error levels. should be ordered in increasing severity
            public static final int LEVEL_SECTIONBREAK = 0;
            public static final int LEVEL_INFO = 1;
            public static final int LEVEL_WARN = 2;
            public static final int LEVEL_ERROR = 3;
            
            /** Children */
            private Vector children;
            
            /** Parent pointer. */
            private OpenPGPLoggerEntry parent;

            /** Level */
            private int level;
            /** Message */
            private String message;
           
            /** Create a new log entry. */
            public OpenPGPLoggerEntry(OpenPGPLoggerEntry parent, int level, String message) {
                this.parent = parent;
                this.level = level;
                this.message = message;
            }
            
            /** Return the parent. */
            public OpenPGPLoggerEntry getParent() {
                return parent;
            }
            
            /** Return the level. */
            public int getLevel() {
                return level;
            }
            
            /** Return the message. */
            public String getMessage() {
                return message;
            }
            
            /** <p>Print message. Does not process children.</p> */
            public String toString() {
                switch (getLevel()) {
                    case LEVEL_SECTIONBREAK : return "--- " + getMessage() + " ---";
                    case LEVEL_INFO : return "INFO: " + getMessage();
                    case LEVEL_WARN : return "WARNING: " + getMessage();
                    case LEVEL_ERROR : return "ERROR: " + getMessage();
                }
                
                return getMessage();
            }
            
            /** Add a sub log entry to this log entry. */
            public void addChildren(OpenPGPLoggerEntry log) {
                if (children==null) children = new Vector();
                
                children.add(log);
            }
            
            /** Get the logs children */
            public OpenPGPLoggerEntry [] getChildren() {
                
                if (children!=null) {
                    OpenPGPLoggerEntry tmp [] = new OpenPGPLoggerEntry[children.size()];
                    for (int n = 0; n < children.size(); n++)
                        tmp[n] = (OpenPGPLoggerEntry)children.elementAt(n);
                    
                    return tmp;
                } 
                
                return null;
            }  
        }
        
        
        
        /** Log, start with email section */
        private OpenPGPLoggerEntry log;
        
        /** Current log entry. */
        private OpenPGPLoggerEntry current;
        
        /** Log creation date. */
        private Date createDate;
        
        /** Section */
        private int section;
        
        /**
         * <p>Create a new log.</p>
         */
        public OpenPGPLogger() {
            createDate = new Date();
            current = null;
        }

        /** Begin a log section. */
        public void beginSection(String message) {
            
            OpenPGPLoggerEntry tmp = null;
            
            if (log == null) {
                tmp = new OpenPGPLoggerEntry(null, OpenPGPLoggerEntry.LEVEL_SECTIONBREAK, message);
                log = tmp;
            } else {
                tmp = new OpenPGPLoggerEntry(current, OpenPGPLoggerEntry.LEVEL_SECTIONBREAK, message);
                current.addChildren(tmp);
            }
            
            current = tmp;
        }
        
        /** End a log section and step back in the stack. */
        public void endSection() {
            if (current!=null)
                current = current.getParent();
        }
        
        /** Logging method used by other log methods. */
        protected void log(int level, String message) {
            if (current!=null) {
                OpenPGPLoggerEntry tmp = new OpenPGPLoggerEntry(current, level, message);
                current.addChildren(tmp);
            }
        }
             
        /** 
         * <p>Write an Info message to the log.</p>
         */
        public void logInfo(String message) {
            log(OpenPGPLoggerEntry.LEVEL_INFO, message);
        }
        
        /** 
         * <p>Write an Warning message to the log.</p>
         */
        public void logWarning(String message) {
            log(OpenPGPLoggerEntry.LEVEL_WARN, message);
        }
        
        /** 
         * <p>Write an Error message to the log.</p>
         */
        public void logError(String message) {
            log(OpenPGPLoggerEntry.LEVEL_ERROR, message);
        }
        

        /** 
         * <p>Return the log's create date.</p>
         */
        public Date getCreateDate() {
            return createDate;
        }
        
        /**
	 * <p>Write a string to a logging stream.</p>
         */
        private void writeLog(OutputStream out, String log) throws IOException {
            out.write(log.getBytes());
        }

        
        /** <p>Render a summary log.</p>
         * @param out Stream to output messages to.
         * @param node Node to start processing from.
         * @param outputLevel Level to output. Only messages >= outputLevel are outputted. -1 denotes no output.
         * @return The level of the most severe problem encountered. OpenPGPLoggerEntry.LEVEL_SECTIONBREAK or OpenPGPLoggerEntry.LEVEL_INFO denote no error.
         */
        private int processSummaryLog(OutputStream out, OpenPGPLoggerEntry node, int outputLevel) throws IOException {
           
            int status = node.getLevel();
            
            // write out warnings
            if ((status!=-1) && (status >= outputLevel)) {
                writeLog(out, node.toString() + "\r\n");
            }

            OpenPGPLoggerEntry tmp[] = node.getChildren();
            if (tmp!=null)
                for (int n = 0; n < tmp.length; n++) {
                    int childStatus = processSummaryLog(out, tmp[n], outputLevel);
                    
                    // If child has a higher priority message then return that
                    if (childStatus > status) status = childStatus;
                }
            
            return status;
        }
        
        /** <p>Output a full log to a stream.</p>
         * <p>This method will recursively output the entire log body in a nice way.</p>
         * @param out Stream to output messages to.
         * @param node Node to start processing from.
         * @param depth Depth of indentation. When used by your code this should be set to 0.
         */
        private void processLog(OutputStream out, OpenPGPLoggerEntry node, int depth) throws IOException {
            
            // indent
            for (int n = 0; n < depth; n++)
                writeLog(out, "     ");
            
            // write message
            writeLog(out, node.toString() + "\r\n");
            
            // write children
            OpenPGPLoggerEntry tmp[] = node.getChildren();
            if (tmp!=null)
                for (int n = 0; n < tmp.length; n++) {
                    processLog(out, tmp[n], depth+1);
                }
        }
        
        /** 
         * <p>Generate a full log.</p>
         * <p>Returns a byte array containing a full log complete with headers.</p>
         */
        public byte [] getLog() throws IOException {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            
                writeLog(out, "****************************************************************************\r\n");
                writeLog(out, "Oxford Brookes Secure Email Project (" + core.CoreVersionInfo.website + ")\r\n");
                writeLog(out, "Secure Email Proxy v" + core.CoreVersionInfo.version + "\r\n");
                writeLog(out, "****************************************************************************\r\n");
                writeLog(out, "Log started at: " + getCreateDate().toString() + "\r\n");
                writeLog(out, "****************************************************************************\r\n");
                
                processLog(out, log, 0);
                
                writeLog(out, "****************************************************************************\r\n");

            return out.toByteArray();
        }
        
        /**
         * <p>Get summary text for the top of the email.</p>
         */
        public byte [] getSummary() throws IOException {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            
                writeLog(out, "****************************************************************************\r\n");
                writeLog(out, "Oxford Brookes Secure Email Project (" + core.CoreVersionInfo.website + ")\r\n");
                writeLog(out, "Secure Email Proxy v" + core.CoreVersionInfo.version + "\r\n");
                writeLog(out, "****************************************************************************\r\n");
                
                int status = processSummaryLog(out, log, OpenPGPLoggerEntry.LEVEL_WARN);
      
                switch (status) {
                    case OpenPGPLoggerEntry.LEVEL_SECTIONBREAK :
                    case OpenPGPLoggerEntry.LEVEL_INFO : writeLog(out, "Message processed OK."); break;
                    case OpenPGPLoggerEntry.LEVEL_WARN : writeLog(out, "WARNINGS encountered while processing, see log for details."); break;
                    case OpenPGPLoggerEntry.LEVEL_ERROR : writeLog(out, "ERRORS encountered while processing, see log for details."); break;
                }

                writeLog(out, "\r\n");
                writeLog(out, "****************************************************************************\r\n");
                writeLog(out, "\r\n");

            return out.toByteArray();

        }
    }

}
