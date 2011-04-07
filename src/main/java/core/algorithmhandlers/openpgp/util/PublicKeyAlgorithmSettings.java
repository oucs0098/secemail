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

package core.algorithmhandlers.openpgp.util;
import core.exceptions.AlgorithmException;
import java.lang.String;

/**
 * <p>A class that returns settings for the public key algorithm, translating the algorithm code into a public key cipher.</p>
 */
public class PublicKeyAlgorithmSettings {
    
    public static final int RSA_ENCRYPTSIGN = 1;
    public static final int RSA_ENCRYPT = 2;
    public static final int RSA_SIGN = 3;
    public static final int ELGAMAL_ENCRYPT = 16;
    public static final int DSA = 17;
    
    /**
     * <p>A method that returns a correctly formatted cipher text string for creating a JCE cipher.</p>
     * @throws AlgorithmException if the requested algorithm is not supported.
     */
    public static String getCipherText(int algorithm) throws AlgorithmException {
        switch (algorithm) {
            case RSA_ENCRYPTSIGN :
            case RSA_ENCRYPT :
            case RSA_SIGN : return "RSA";
            
            case ELGAMAL_ENCRYPT : return "ElGamal";
            
            case DSA : return "DSA";
            
            default : throw new AlgorithmException("Requested public key algorithm (" + algorithm + ") not supported.");
        }
    }
    
    /** A method that returns a formatted cipher text string for display. */
    public static String getCipherDisplayText(int algorithm) {
        switch (algorithm) {
            case RSA_ENCRYPTSIGN :
            case RSA_ENCRYPT :
            case RSA_SIGN : return "RSA";
            	
            case ELGAMAL_ENCRYPT : return "El Gamal";
            	
            case DSA : return "DSA";
            
            default: return "Unknown";
        }
    }
    
    /**
     * <p>A method for returning the default mode for a given cipher.</p>
     * @throws AlgorithmException if the requested algorithm is not supported.
     */
    public static String getModeText(int algorithm) throws AlgorithmException {
        switch (algorithm) {
            case RSA_ENCRYPTSIGN :
            case RSA_ENCRYPT :
            case RSA_SIGN : 
            
            case ELGAMAL_ENCRYPT : 
            
            case DSA : return "ECB";
            default : throw new AlgorithmException("Requested public key algorithm (" + algorithm + ") not supported.");
        }
    }
    
    /**
     * <p>A method for returning the default padding for a given cipher.</p>
     * @throws AlgorithmException if the requested algorithm is not supported.
     */
    public static String getPaddingText(int algorithm) throws AlgorithmException {
        switch (algorithm) {
            case RSA_ENCRYPTSIGN :
            case RSA_ENCRYPT :
            case RSA_SIGN : 
            
            case ELGAMAL_ENCRYPT : 
            
            case DSA : return "PKCS1Padding";
            default : throw new AlgorithmException("Requested public key algorithm (" + algorithm + ") not supported.");
        }
    }
    
    /**
     * <p>A method for returning the default key size for a given cipher.</p>
     * <p>This is really only used when generating new keys.</p>
     * @throws AlgorithmException if the requested algorithm is not supported.
     */
    public static int getDefaultKeySize(int algorithm) throws AlgorithmException {
        switch (algorithm) {
            case RSA_ENCRYPTSIGN :
            case RSA_ENCRYPT :
            case RSA_SIGN :
            case DSA :
            case ELGAMAL_ENCRYPT : return 1024;
            
            default : throw new AlgorithmException("Requested public key algorithm (" + algorithm + ") not supported.");
        }
    }
    
    /** Get the text that needs to be added to the hash algorithm text to produce a signer.
     * @throws AlgorithmException if the requested algorithm is not supported.
     */
    public static String getSignatureAlgorithmTailText(int algorithm) throws AlgorithmException {
        switch (algorithm) {
            case RSA_ENCRYPTSIGN :
            case RSA_ENCRYPT :
            case RSA_SIGN : return "withRSA";
            
            case DSA : return "withDSA";
            
            default : throw new AlgorithmException("Requested signature algorithm (" + algorithm + ") not supported.");
        }
    }
    
    /** A convenient method to return the full text needed to create a given cipher.
     * @throws AlgorithmException if the requested algorithm is not supported.
     */
    public static String getFullCipherText(int algorithm) throws AlgorithmException {
        return PublicKeyAlgorithmSettings.getCipherText(algorithm) + "/" + PublicKeyAlgorithmSettings.getModeText(algorithm) + "/" + PublicKeyAlgorithmSettings.getPaddingText(algorithm);
    }
    
    /* Quick test methods ****************************************************/
    
    /** A quick test method that returns true if algorithm is an RSA algorithm. 
     * @throws AlgorithmException if the requested algorithm is not supported.
     */
    public static boolean isRSA(int algorithm) throws AlgorithmException {
        if (getCipherText(algorithm).compareTo("RSA")==0)
            return true;
        else
            return false;
    }
    
    /** A quick test method that returns true if algorithm is an DSA algorithm. 
     * @throws AlgorithmException if the requested algorithm is not supported.
     */
    public static boolean isDSA(int algorithm) throws AlgorithmException {
        if (getCipherText(algorithm).compareTo("DSA")==0)
            return true;
        else
            return false;
    }
    
    /** A quick test method that returns true if algorithm is an Elgamal algorithm. 
     * @throws AlgorithmException if the requested algorithm is not supported.
     */
    public static boolean isElGamal(int algorithm) throws AlgorithmException {
        if (getCipherText(algorithm).compareTo("ElGamal")==0)
            return true;
        else
            return false;
    }
    
    /** A quick test method to return true if algorithm is a signing algorithm.
     * @throws AlgorithmException if the requested algorithm is not supported.
     */
    public static boolean canSign(int algorithm) throws AlgorithmException {
    	switch (algorithm) {
	        case RSA_ENCRYPTSIGN :
	        case RSA_SIGN :
	        case DSA : return true;
	        
	        case RSA_ENCRYPT :
	        case ELGAMAL_ENCRYPT : return false;
	        
	        default : throw new AlgorithmException(
	        		"Public key algorithm (" + algorithm + ") not supported.");
	    }
    }
    
    /** A quick test method to return true if algorithm is an encrypting algorithm.
     * @throws AlgorithmException if the requested algorithm is not supported.
     */
    public static boolean canEncrypt(int algorithm) throws AlgorithmException {
    	switch (algorithm) {
	        case RSA_ENCRYPTSIGN :
	        case RSA_ENCRYPT :
	        case ELGAMAL_ENCRYPT : return true;
	        
	        case RSA_SIGN :
	        case DSA : return false;
	        
	        default : throw new AlgorithmException(
	        		"Public key algorithm (" + algorithm + ") not supported.");
	    }
    }
    
}
