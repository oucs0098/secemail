package ui;

import core.algorithmhandlers.PassPhraseRequester;
import core.algorithmhandlers.PassPhraseResponse;

/** Class to help the separation of core and UI */
public class PassPhraseDialogGenerator implements PassPhraseRequester {

	/* (non-Javadoc)
	 * @see core.algorithmhandlers.PassPhraseRequester#requestPassPhrase(
	 * java.lang.String, java.lang.String)
	 */
	public PassPhraseResponse requestPassPhrase(String title, String message) {
		EnterPassphraseDlg dlg = new EnterPassphraseDlg(
				title, message, new javax.swing.JFrame(), true, false);
		PassphraseDlgReturnValue response = dlg.showPasswordDialog();
		return response;
	}

}
