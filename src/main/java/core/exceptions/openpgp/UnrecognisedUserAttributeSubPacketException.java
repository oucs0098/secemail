package core.exceptions.openpgp;

import core.exceptions.AlgorithmException;

/** <p>An exception thrown by user attribute classes when an unrecognised subpacket
 * is encountered.</p>
 * <p>According to the OpenPGP RFC this error should be quietly ignored.</p>
 */
public class UnrecognisedUserAttributeSubPacketException extends
		AlgorithmException
{
	/** Creates a new instance of UnrecognisedSignatureSubPacketException */
	public UnrecognisedUserAttributeSubPacketException( String message )
	{
		super( message );
	}
}
