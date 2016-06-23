package org.wso2.custom.crypto.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.wso2.securevault.CipherFactory;
import org.wso2.securevault.CipherOperationMode;
import org.wso2.securevault.DecryptionProvider;
import org.wso2.securevault.EncodingType;
import org.wso2.securevault.EncryptionProvider;
import org.wso2.securevault.SecureVaultException;
import org.wso2.securevault.commons.MiscellaneousUtil;
import org.wso2.securevault.definition.CipherInformation;
import org.wso2.securevault.definition.IdentityKeyStoreInformation;
import org.wso2.securevault.definition.KeyStoreInformationFactory;
import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;
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
import java.security.Security;
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
//        String[] arg = {"smb://user1:pass@smb.host/project1"};
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
        String provider = null;
        String algorithm = null;
        String cipherType = null;
        EncodingType inType = null;
        EncodingType outType = null;

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

        // Create a KeyStore Information for private key entry KeyStore
        IdentityKeyStoreInformation identityInformation =
                KeyStoreInformationFactory.createIdentityKeyStoreInformation(properties);


        try {

            String identityKeyPass = null;
            String identityStorePass = null;
            if (identityInformation != null) {
                identityKeyPass = identityInformation
                        .getKeyPasswordProvider().getResolvedSecret();
                identityStorePass = identityInformation
                        .getKeyStorePasswordProvider().getResolvedSecret();
            }

            if (!Util.validatePasswords(identityStorePass, identityKeyPass)) {
                log.error("Either Identity or Trust keystore password is mandatory" +
                          " in order to initialized secret manager.");
                return;
            }

            IdentityKeyStoreWrapper identityKeyStoreWrapper = new IdentityKeyStoreWrapper();
            identityKeyStoreWrapper.init(identityInformation, identityKeyPass);

            algorithm = MiscellaneousUtil.getProperty(properties, Constants.CIPHER_ALGORITHM,
                                                      Constants.CIPHER_ALGORITHM_DEFAULT);

            provider = MiscellaneousUtil.getProperty(properties, Constants.SECURITY_PROVIDER,
                                                     null);
            cipherType = MiscellaneousUtil.getProperty(properties, Constants.CIPHER_TYPE,
                                                       null);
            inType = MiscellaneousUtil.getProperty(properties, Constants.INPUT_ENCODE_TYPE,
                                                   Constants.INPUT_ENCODE_TYPE_DEFAULT, EncodingType.class);
            outType = MiscellaneousUtil.getProperty(properties, Constants.OUTPUT_ENCODE_TYPE,
                                                    Constants.OUTPUT_ENCODE_TYPE_DEFAULT, EncodingType.class);

            CipherInformation cipherInformation = new CipherInformation();
            cipherInformation.setAlgorithm(algorithm);
            cipherInformation.setCipherOperationMode(CipherOperationMode.ENCRYPT);
            cipherInformation.setInType(EncodingType.BASE64); //TODO
            cipherInformation.setType(cipherType);
            cipherInformation.setInType(inType);
            cipherInformation.setOutType(outType);

            if (provider != null && !provider.isEmpty()) {
                if (provider.equals("BC")) {
                    Security.addProvider(new BouncyCastleProvider());
                    cipherInformation.setProvider(provider);
                }
                //todo need to add other providers if there are any.
            }

            EncryptionProvider baseCipher = CipherFactory.createCipher(cipherInformation, identityKeyStoreWrapper);
            byte[] encryptedPassword = baseCipher.encrypt(args[0].getBytes());
            String encodedValue = new String(encryptedPassword);
            log.info("Encrypted and Base64 encoded value - " + encodedValue);
            log.info("******************************** End encryption ********************************");
        } catch (SecureVaultException e) {
            log.error("SecureVault exception, " + e.getMessage(), e);
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
