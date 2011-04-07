package core.algorithmhandlers;

/** 
 * interface to help decouple the application from the core classes
 */
public interface PassPhraseRequester {
	
	/** request a pass phrase from the application */
	PassPhraseResponse requestPassPhrase(String title, String message);
	
}