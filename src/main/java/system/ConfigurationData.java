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

package system;
import java.io.*;
import java.util.*;

/**
 * <p>A generic (and very basic) configuration loader.</p> 
 * <p>Acts as a wrapper for java.util.Properties.</p>
 * <p>Configuration settings are written in the file as VariableName=Value.</p>
 */
public class ConfigurationData {
    
    /** Storage for the configuration elements. */
    private Properties properties;
    
    /** The filename of the configuration file. */
    private String fileName;
    
    /** <p>Creates a new instance of this class.</p>
     * <p>Will load all the settings in a given resource file into memory and lets you query it. Any changes
     * you make to the values will not be saved until you call SaveConfig().</p>
     * @param file The configuration file to load, if this doesn't exist it is created.
     * @throws IOException should something go wrong.
     */
    public ConfigurationData(String file) throws IOException {
        fileName = file;
        
        File f = new File(fileName);
        f.createNewFile();
        
        properties = new Properties();
        
        loadConfig();
    }
    
    /** <p>Loads configuration settings from the file. </p>
     * @throws IOException should anything go amiss
     */
    public void loadConfig() throws IOException {
        properties.load(new FileInputStream(fileName));
    }
    
    /** <p>Save configuration settings to the file. </p>
     * <p>Will clobber any existing file. Entries with no value will not be written.</p>
     * @throws IOException should anything go amiss
     */
    public void saveConfig() throws IOException {
        FileWriter f = new FileWriter(fileName);
        String header = "Oxford Brookes University Secure Email Proxy v" + core.CoreVersionInfo.version;
        
        f.write("# " + header);
        f.write("\n");
        
        TreeMap map = new TreeMap(properties);
        Iterator entries = map.entrySet().iterator();    
        
        Map.Entry entry;
        
        while (entries.hasNext()) {
            entry = (Map.Entry) entries.next();
            if ("".compareTo(entry.getValue().toString())!=0)
                f.write(entry.getKey() + "=" + entry.getValue() + "\n");
        }

        f.close();
    }
    
    /** <p>Retrieves the value to a setting.</p>
     * <p>Returns the value of a given setting, or return the passed default value if the setting is not found.</p>
     * <p>If the value is not found, the value setting will be set to dflt (to ensure that the config file is created in its entirety on startup).</p>
     * @param setting The setting to return the value of.
     * @param dflt The default value of the setting to return if setting isn't found.
     */
    public String getSetting(String setting, String dflt) {
       //return properties.getProperty(setting, dflt);
        String tmp = properties.getProperty(setting, dflt);
        if (tmp.compareTo(dflt)==0)
            setSetting(setting, dflt);
        
        return tmp;
    }
    
    /** <p>Sets the value of a given setting.</p>
     * <p>Sets the value of a given setting, will create an entry if one does not exist.</p>
     * <p>Settings will not be saved to the file until you call SaveConfig().</p>
     * @param setting The setting name.
     * @param value The setting's value.
     */
    public void setSetting(String setting, String value) {
        properties.setProperty(setting, value);
    }
}