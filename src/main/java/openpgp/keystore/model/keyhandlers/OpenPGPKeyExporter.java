package openpgp.keystore.model.keyhandlers;

import core.exceptions.KeyHandlerException;
import java.io.IOException;
import openpgp.keystore.model.*;

/** Interface defining methods for exporting keys.
 * @version $Id: OpenPGPKeyExporter.java,v 1.2 2007-08-27 21:16:28 nigelb Exp $
 */
public interface OpenPGPKeyExporter {
    
    /** <p>Method to export an OpenPGP private certificate, the primary signing 
	 * key with all existing exportable user IDs, exportable signatures, and 
	 * private subkeys.</p>
	 * @param key The certificate to export
	 * @param append Whether to append to the resource (for file-based resources)
	 */
    public void exportPrivateCertificate(PrimarySigningKey key, boolean append)
			throws IOException, KeyHandlerException;
    
    /** <p>Method to export a private OpenPGP key store, containing private 
     * certificates, the primary signing keys with all existing exportable user
     * IDs, exportable signatures, and private subkeys.</p>
	 * @param keyStore The key store to export
	 */
    public void exportPrivateKeyring(KeyStore keyStore) throws IOException,
			KeyHandlerException;
    
    /** <p>Method to export an OpenPGP public certificate, the primary signing 
	 * key with all existing exportable user IDs, exportable signatures, and 
	 * private subkeys.</p>
	 * @param key The certificate to export
	 * @param append Whether to append to the resource (for file-based resources)
	 */
    public void exportPublicCertificate(PrimarySigningKey key, boolean append)
			throws IOException, KeyHandlerException;
    
    /** <p>Method to export a public OpenPGP key store, containing public 
     * certificates, the primary signing keys with all existing exportable user
     * IDs, exportable signatures, and private subkeys.</p>
	 * @param keyStore The key store to export
	 */
    public void exportPublicKeyring(KeyStore keyStore) throws IOException,
			KeyHandlerException;
    
}
