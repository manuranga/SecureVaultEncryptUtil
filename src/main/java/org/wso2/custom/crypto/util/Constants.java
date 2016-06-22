package org.wso2.custom.crypto.util;

/**
 * This is a interface to hold required constant values.
 */
public interface Constants {
    /* Private key entry KeyStore location */
    public final static String IDENTITY_KEY_STORE = "keystore.identity.location";
    /* User name for access keyStore*/
    public final static String IDENTITY_KEY_STORE_USER_NAME = "keystore.identity.store.username";
    /* Password for access keyStore*/
    public final static String IDENTITY_KEY_STORE_PASSWORD = "keystore.identity.store.password";
    /* Alias for private key entry KeyStore */
    public final static String IDENTITY_KEY_STORE_ALIAS = "keystore.identity.alias";
    /* Private key entry KeyStore type  */
    public final static String IDENTITY_KEY_STORE_TYPE = "keystore.identity.type";
    public final static String IDENTITY_KEY_STORE_PARAMETERS = "keystore.identity.parameters";

    /* User name for get private key*/
    public final static String IDENTITY_KEY_USER_NAME = "keystore.identity.key.username";
    /* Password for get private key*/
    public final static String IDENTITY_KEY_PASSWORD = "keystore.identity.key.password";
    /* Cipher algorithm to be used*/
    public final static String CIPHER_ALGORITHM = "cipher.algorithm";
    /* Default Cipher algorithm to be used*/
    public final static String CIPHER_ALGORITHM_DEFAULT = "RSA";

    public final static String PROPERTIES_FILE_PATH_DEFAULT = "secureVault.properties";

}
