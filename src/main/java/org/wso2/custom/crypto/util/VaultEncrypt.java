package org.wso2.custom.crypto.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.securevault.definition.IdentityKeyStoreInformation;
import org.wso2.securevault.definition.KeyStoreInformationFactory;
import sun.misc.BASE64Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Properties;

/**
 * This class provide basic encrypt functionality
 */
public class VaultEncrypt {
    private static Log log = LogFactory.getLog(VaultEncrypt.class);

    /**
     * Main method.
     *
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        String[] arg = {"WSO2", "Pass"};
        encrypt(args);
    }

    /**
     * Method to run encryption.
     *
     * @param args
     * @throws Exception
     */
    public static void encrypt(String[] args) {
        log.info("******************************** Start encryption ********************************");
        if (args.length != 1 && args.length != 2) {
            log.error("Invalid number of parameters, found - " + args.length + ", required - 3");
            return;
        }
        String propertiesFile = null;
        if (args.length >= 2) {
            propertiesFile = args[1];
        }

        if (propertiesFile == null || propertiesFile.isEmpty()) {
            log.warn("Properties file(secureVault.properties) path not provided, hence defaulting to 'secureVault.properties'");
            propertiesFile = Constants.PROPERTIES_FILE_PATH_DEFAULT;
        }

        Properties properties = Util.loadProperties(propertiesFile);

        String keyStoreFile = null;
        String keyType = null;
        String aliasName = null;
        String password = null;
        String provider = null;
        Cipher cipher = null;

        keyStoreFile = properties.getProperty(Constants.IDENTITY_KEY_STORE);

        if (keyStoreFile == null) {
            log.error("Keystore file path cannot be null");
            return;
        }

        File keyStore = new File(keyStoreFile);

        if (!keyStore.exists()) {
            log.error("Cannot find given keystore file - " + keyStore);
            return;
        }

        keyType = properties.getProperty(Constants.IDENTITY_KEY_STORE_TYPE);

        aliasName = properties.getProperty(Constants.IDENTITY_KEY_STORE_ALIAS);

        // Create a KeyStore Information for private key entry KeyStore
        IdentityKeyStoreInformation identityInformation =
                KeyStoreInformationFactory.createIdentityKeyStoreInformation(properties);


        password = identityInformation.getKeyPasswordProvider().getResolvedSecret();
        if (password == null) {
            log.error("KeyStore password can not be null");
            return;
        }
        if (keyType == null) {
            log.error("KeyStore Type can not be null");
            return;
        }

        try {
            KeyStore primaryKeyStore = getKeyStore(keyStoreFile, password, keyType, provider);
            Certificate certs = primaryKeyStore.getCertificate(aliasName);
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, certs);
            byte[] encryptedPassword = cipher.doFinal(args[0].getBytes());
            BASE64Encoder encoder = new BASE64Encoder();
            String encodedValue = encoder.encode(encryptedPassword);
            log.info("Encrypted and Base64 encoded value - " + encodedValue);
            log.info("******************************** End encryption ********************************");
        } catch (InvalidKeyException e) {
            log.error("Invalid key provided, " + e.getMessage(), e);
        } catch (NoSuchAlgorithmException e) {
            log.error("No such algorithm, " + e.getMessage(), e);
        } catch (KeyStoreException e) {
            log.error("Keystore error, " + e.getMessage(), e);
        } catch (NoSuchPaddingException e) {
            log.error("Padding error, " + e.getMessage(), e);
        } catch (BadPaddingException e) {
            log.error("Bad padding, " + e.getMessage(), e);
        } catch (IllegalBlockSizeException e) {
            log.error("Illegal blocking size, " + e.getMessage(), e);
        } catch (CertificateException e) {
            log.error("Certificate Error, " + e.getMessage(), e);
        } catch (NoSuchProviderException e) {
            log.error("No such provider, " + e.getMessage(), e);
        } catch (IOException e) {
            log.error("IO error, " + e.getMessage(), e);
        }
    }


    /**
     * get the primary key store instant
     *
     * @param location      location of key store
     * @param storePassword password of key store
     * @param storeType     key store type
     * @param provider      key store provider
     * @return KeyStore instant
     */
    private static KeyStore getKeyStore(String location, String storePassword, String storeType,
                                        String provider)
            throws IOException, NoSuchProviderException, KeyStoreException, CertificateException,
                   NoSuchAlgorithmException {

        File keyStoreFile = new File(location);

        BufferedInputStream bufferedInputStream = null;
        try {
            bufferedInputStream = new BufferedInputStream(new FileInputStream(keyStoreFile));
            KeyStore keyStore;
            if (provider != null) {
                keyStore = KeyStore.getInstance(storeType, provider);
            } else {
                keyStore = KeyStore.getInstance(storeType);
            }
            keyStore.load(bufferedInputStream, storePassword.toCharArray());
            return keyStore;
        } finally {
            if (bufferedInputStream != null) {
                try {
                    bufferedInputStream.close();
                } catch (IOException ignored) {
                    log.error("Error while closing input stream");
                }
            }
        }
    }

}
