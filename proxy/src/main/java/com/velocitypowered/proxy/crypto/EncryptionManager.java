/*
 * Copyright (C) 2018-2023 Velocity Contributors
 * Current Date and Time (UTC): 2025-06-13 18:15:46
 * Current User's Login: Khoasoma
 */

package com.velocitypowered.proxy.security.crypto;

import com.google.common.base.Preconditions;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EncryptionManager {
    private static final Logger logger = LogManager.getLogger(EncryptionManager.class);
    private static final String ENCRYPTION_TYPE = "AES/GCM/NoPadding";
    private static final int IV_SIZE = 12;
    private static final int TAG_SIZE = 16;
    
    private final KeyPair serverKeyPair;
    private final ConcurrentHashMap<String, SecretKey> sessionKeys;
    private final int keySize;
    private final SecureRandom secureRandom;

    public EncryptionManager(int keySize) {
        this.keySize = keySize;
        this.sessionKeys = new ConcurrentHashMap<>();
        this.secureRandom = new SecureRandom();
        this.serverKeyPair = generateKeyPair();
    }

    private KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(keySize, secureRandom);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            logger.error("Failed to generate key pair", e);
            throw new RuntimeException("Failed to initialize encryption", e);
        }
    }

    public void initialize() {
        try {
            // Test encryption/decryption
            byte[] testData = "test".getBytes();
            SecretKey testKey = generateSecretKey();
            byte[] encrypted = encrypt(testData, testKey);
            byte[] decrypted = decrypt(encrypted, testKey);

            if (!Arrays.equals(testData, decrypted)) {
                throw new RuntimeException("Encryption test failed");
            }

            logger.info("Encryption manager initialized successfully");
        } catch (Exception e) {
            logger.error("Failed to initialize encryption manager", e);
            throw new RuntimeException("Failed to initialize encryption", e);
        }
    }

    public SecretKey generateSecretKey() {
        try {
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(256, secureRandom);
            return generator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            logger.error("Failed to generate secret key", e);
            throw new RuntimeException(e);
        }
    }

    public byte[] generateIv() {
        byte[] iv = new byte[IV_SIZE];
        secureRandom.nextBytes(iv);
        return iv;
    }

    public byte[] encrypt(byte[] data, SecretKey key) {
        Preconditions.checkNotNull(data, "data");
        Preconditions.checkNotNull(key, "key");

        try {
            byte[] iv = generateIv();
            Cipher cipher = Cipher.getInstance(ENCRYPTION_TYPE);
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

            byte[] encrypted = cipher.doFinal(data);
            byte[] combined = new byte[iv.length + encrypted.length];
            
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
            
            return combined;
        } catch (Exception e) {
            logger.error("Failed to encrypt data", e);
            throw new RuntimeException("Encryption failed", e);
        }
    }

    public byte[] decrypt(byte[] encryptedData, SecretKey key) {
        Preconditions.checkNotNull(encryptedData, "encryptedData");
        Preconditions.checkNotNull(key, "key");

        try {
            // Extract IV
            byte[] iv = Arrays.copyOfRange(encryptedData, 0, IV_SIZE);
            byte[] cipherText = Arrays.copyOfRange(encryptedData, IV_SIZE, encryptedData.length);

            Cipher cipher = Cipher.getInstance(ENCRYPTION_TYPE);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            
            return cipher.doFinal(cipherText);
        } catch (Exception e) {
            logger.error("Failed to decrypt data", e);
            throw new RuntimeException("Decryption failed", e);
        }
    }

    public void addSessionKey(String sessionId, SecretKey key) {
        sessionKeys.put(sessionId, key);
    }

    public SecretKey getSessionKey(String sessionId) {
        return sessionKeys.get(sessionId);
    }

    public void removeSessionKey(String sessionId) {
        sessionKeys.remove(sessionId);
    }

    public KeyPair getServerKeyPair() {
        return serverKeyPair;
    }

    public boolean validateKey(SecretKey key) {
        try {
            // Validate key size
            if (key.getEncoded().length * 8 != 256) {
                return false;
            }

            // Test encryption/decryption
            byte[] testData = "test".getBytes();
            byte[] encrypted = encrypt(testData, key);
            byte[] decrypted = decrypt(encrypted, key);

            return Arrays.equals(testData, decrypted);
        } catch (Exception e) {
            logger.error("Key validation failed", e);
            return false;
        }
    }

    public byte[] sign(byte[] data) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(serverKeyPair.getPrivate());
            signature.update(data);
            return signature.sign();
        } catch (Exception e) {
            logger.error("Failed to sign data", e);
            throw new RuntimeException("Signing failed", e);
        }
    }

    public boolean verify(byte[] data, byte[] signatureBytes, PublicKey publicKey) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(data);
            return signature.verify(signatureBytes);
        } catch (Exception e) {
            logger.error("Failed to verify signature", e);
            return false;
        }
    }
}