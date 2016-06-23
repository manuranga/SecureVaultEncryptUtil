package org.wso2.custom.crypto.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * This is a util class to provide required functions.
 */
public class Util {
    private static Log log = LogFactory.getLog(Util.class);

    /**
     * Helper method to load properties file.
     *
     * @param filePath
     * @return properties
     */
    public static Properties loadProperties(String filePath) {
        Properties properties = new Properties();
        File dataSourceFile = new File(filePath);
        if (!dataSourceFile.exists()) {
            return properties;
        }

        InputStream in = null;
        try {
            in = new FileInputStream(dataSourceFile);
            properties.load(in);
        } catch (IOException e) {
            String msg = "Error loading properties from a file at :" + filePath;
            log.warn(msg, e);
            return properties;
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ignored) {

                }
            }
        }
        return properties;
    }

    /**
     * Helper method to validate store password and key password
     *
     * @param identityStorePass
     * @param identityKeyPass
     * @return if valid true, false otherwise
     */
    public static boolean validatePasswords(String identityStorePass,
                                      String identityKeyPass) {
        boolean isValid = false;
        if (identityStorePass != null && !"".equals(identityStorePass) &&
            identityKeyPass != null && !"".equals(identityKeyPass)) {
            if (log.isDebugEnabled()) {
                log.debug("Identity Store Password " +
                          "and Identity Store private key Password cannot be found.");
            }
            isValid = true;
        }
        return isValid;
    }
}
