/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

/**
 *
 * @author ashikreji
 */
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

public class CryptoUtil {
    private static final String AES = "AES";
    private static final String HMAC_SHA256 = "HmacSHA256";

    public static String encrypt(String plainText, String masterSecret) throws Exception {
        String encryptionKeyBase64 = KeyDerivationUtil.deriveKey(masterSecret, "encryption");
        byte[] keyBytes = Base64.getDecoder().decode(encryptionKeyBase64);
        SecretKeySpec aesKey = new SecretKeySpec(keyBytes, 0, 16, AES); 
        
        Cipher cipher = Cipher.getInstance(AES);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String cipherText, String masterSecret) throws Exception {
        String encryptionKeyBase64 = KeyDerivationUtil.deriveKey(masterSecret, "encryption");
        byte[] keyBytes = Base64.getDecoder().decode(encryptionKeyBase64);
        SecretKeySpec aesKey = new SecretKeySpec(keyBytes, 0, 16, AES); 
        
        Cipher cipher = Cipher.getInstance(AES);
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    public static String generateHmac(String data, String masterSecret) throws Exception {
        String macKeyBase64 = KeyDerivationUtil.deriveKey(masterSecret, "mac");
        byte[] keyBytes = Base64.getDecoder().decode(macKeyBase64);
        SecretKeySpec secret_key = new SecretKeySpec(keyBytes, 0, 16, HMAC_SHA256); 
        
        Mac sha256_HMAC = Mac.getInstance(HMAC_SHA256);
        sha256_HMAC.init(secret_key);
        byte[] hmacBytes = sha256_HMAC.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hmacBytes);
    }

    public static boolean verifyHmac(String data, String masterSecret, String hmacToVerify) throws Exception {
        String generatedHmac = generateHmac(data, masterSecret);
        return generatedHmac.equals(hmacToVerify);
    }
}
