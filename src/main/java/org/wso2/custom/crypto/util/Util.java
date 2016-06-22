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
}
