package openpgp.keystore.tree;

import javax.swing.Icon;
import javax.swing.ImageIcon;
import java.util.Hashtable;

/** Class to cache icons 
 * @version $Id: IconLoader.java,v 1.2 2007-08-17 17:24:22 nigelb Exp $ 
 */
public class IconLoader {
	
    /** static icon loader allows the cacheing of objects */
    private static IconLoader loader = null;

    /** where we should expect icon resources to be made available */
    private static final String ICON_RESOURCE_AREA = "images/";

    /** the cached icons, indexed by filename */
    private Hashtable iconTable = new Hashtable();

    /** private constructor to restrict adhoc construction of this class */
    private IconLoader() {}

    /** static method, should always return the same object */
    public static IconLoader getInstance() { 
    	// It's probably not necessary to guard against multiple threads, this
    	// is force of habit with cache-type classes...
        if( loader == null ) { // don't obtain lock unless necessary ...
            synchronized( "IMAGELOADERLOCK" ) {
                if( loader == null ) {  // only first accessor initialises
                    loader = new IconLoader();
                }
            }
        }
        return loader;
    }
    
    /** Accessor method
     * @param filename The filename of the icon to be retrieved
     * @return The icon object representing the icon resource
     */
    public Icon getIcon(String filename) {
    	Icon icon;
    	// try the local icon cache first ...
    	icon = (Icon)iconTable.get(filename);
    	if (icon == null) {  // failing that, try to load the icon ...
    		String path = ICON_RESOURCE_AREA + filename;
        	java.net.URL url = IconLoader.class.getResource(path);
        	
        	if (url != null) {  // the resource exists!
        		icon = new ImageIcon(url);
        		iconTable.put(filename, icon);
        	}
    	}
    	return icon;
    }
	
}
