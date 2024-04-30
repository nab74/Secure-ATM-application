/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

/**
 *
 * @author ashikreji
 */
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;


public class ATMClient {
    static String masterSecret = "";
    
    public static void main(String[] args) {
        String hostName = "localhost";
        int portNumber = 12345;        

        try {
            Socket socket = new Socket(hostName, portNumber);
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            String serializedPublicKey = in.readLine();
            PublicKey publicKey = deserializePublicKey(serializedPublicKey);
            
            out.println("mySecretPSK");

            String serverResponse = in.readLine();
            if ("AUTH_SUCCESS".equals(serverResponse)) {
                String encryptedMasterSecret = in.readLine();
                
                try {
                    masterSecret = decryptMasterSecret(encryptedMasterSecret, publicKey);
                    System.out.println("Decrypted Master Secret: " + masterSecret);
                    System.out.println("-----------------------------------------------------------------------------");
                    System.out.println("[Client] Authentication Successful. Master Secret received and decrypted.");
                    System.out.println("-----------------------------------------------------------------------------");

                }
                catch(Exception e){
                     System.err.println("Failed to decrypt Master Secret: " + e.getMessage());
                }
                
                System.out.println("Authentication Successful. Master Secret: " + masterSecret);
                
                String encryptionKey = KeyDerivationUtil.deriveKey(masterSecret, "encryption");
                String macKey = KeyDerivationUtil.deriveKey(masterSecret, "mac");

                System.out.println("Client Encryption Key: " + encryptionKey);
                System.out.println("Client MAC Key: " + macKey);
                
                System.out.println("-----------------------------------------------------------------------------");
                System.out.println("[Client] Encryption and MAC keys derived from the Master Secret.");
                System.out.println("-----------------------------------------------------------------------------");

                BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
               
                System.out.println("Connected to the bank server.");
                
                List<String> auditList = new ArrayList<>();
                java.sql.Timestamp timestamp = new java.sql.Timestamp(System.currentTimeMillis());  
                String strtime=timestamp.toString(); 
                
                String accountNumber = "";
                System.out.println("Enter account number: ");
                accountNumber = stdIn.readLine();
                System.out.println("Enter Password: ");
                String password=stdIn.readLine();
                
                while(true){
                 System.out.println("Enter transaction type (deposit, withdrawal, balance,audit,logout): ");
                 String transactionType = stdIn.readLine();
               
                String amount = "";

                switch (transactionType.toLowerCase()) {
                    case "deposit":                        
                        System.out.println("Enter amount to deposit: ");
                        amount = stdIn.readLine();
                        auditList.add("Account#:"+accountNumber+"|"+"Deposit"+"|"+strtime);
                        break;
                    case "withdrawal":
                        //System.out.println("Enter account number: ");
                       // accountNumber = stdIn.readLine();                       
                        System.out.println("Enter amount to withdraw: ");
                        amount = stdIn.readLine();
                         auditList.add("Account#:"+accountNumber+"|"+"Withdraw"+"|"+strtime);
                        break;
                    case "balance":
                        auditList.add("Account#:"+accountNumber+"|"+"Balance"+"|"+strtime);
                      //  System.out.println("Enter account number for balance inquiry: ");
                     //   accountNumber = stdIn.readLine();
                       // amount = "0"; // 0 here cuz this is a balance check
                        break;
                    case "audit":
                         System.out.println("Audit:");
                     for(int i=0;i<auditList.size();i++){
                       System.out.println(auditList.get(i));
                     }
                     break;
                    case "logout":
                         in.close();
                     out.close();
                     socket.close();
                     throw new Exception();
                        
                    default:
                        System.out.println("Unsupported transaction type. Please enter a valid transaction type.");
                        return; 
                }

                try {
                sendTransaction(transactionType, accountNumber, amount, out, in);

                } catch (Exception e) {
                    System.out.println("Error processing transaction: " + e.getMessage());
                }
                }
            } else {
                System.out.println("Authentication Failed. Closing connection.");
            }
            in.close();
            out.close();
            socket.close();
        } catch (UnknownHostException e) {
            System.err.println("Host unknown: " + hostName);
            e.printStackTrace();
        } catch (IOException e) {
            System.err.println("Couldn't get I/O for the connection to " + hostName);
            e.printStackTrace();
        } catch (Exception ex) {
            System.out.println("Thank You For Using This ATM  :)");
        }        
    }
    private static PublicKey deserializePublicKey(String publicKeyStr) {
        try {
            byte[] publicBytes = Base64.getDecoder().decode(publicKeyStr);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(keySpec);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Failed to deserialize public key", e);
        }
    }

    private static String decryptMasterSecret(String encryptedSecret, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedSecret));
        return new String(decryptedBytes);
    }
    
    private static void sendTransaction(String transactionType, String accountNumber, String amount, PrintWriter out, BufferedReader in) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] nonceBytes = new byte[16]; 
        random.nextBytes(nonceBytes);
        String nonce = Base64.getEncoder().encodeToString(nonceBytes);
        String transactionDetails = transactionType.toUpperCase() + "|" + accountNumber + "|" + amount + "|" + nonce;;

   
     //   if ("BALANCE_INQUIRY".equalsIgnoreCase(transactionType)) {
       //    transactionDetails =  transactionType.toUpperCase() + "|" + accountNumber;
      //  }

    
        String encryptedTransaction = CryptoUtil.encrypt(transactionDetails, masterSecret);
        String transactionMac = CryptoUtil.generateHmac(encryptedTransaction, masterSecret);
        System.out.println("Generated HMAC (client): " + transactionMac);
        out.println(encryptedTransaction + "|" + transactionMac);
        System.out.println("-----------------------------------------------------------------------------");
        System.out.println("[Client] Sent transaction to the server: " + transactionType.toUpperCase());
        System.out.println("-----------------------------------------------------------------------------");

    
        String response = in.readLine();
        String[] parts = response.split("\\|");
        if (parts.length == 2) {
            String encryptedResponse = parts[0];
            String responseMac = parts[1];
        
        

        
        if (CryptoUtil.verifyHmac(encryptedResponse, masterSecret, responseMac)) {
            String decryptedResponse = CryptoUtil.decrypt(encryptedResponse, masterSecret);
            String[] responseParts = decryptedResponse.split("\\|");

            String responseNonce = responseParts[responseParts.length - 1];
            System.out.println("Received Nonce: " + responseNonce);
            if (responseNonce.equals(nonce)) {
                System.out.println("Nonce matches. Response is valid.");
    
            } else {
                System.out.println("Nonce mismatch. Response may be tampered with or incorrect.");
            }

            System.out.println("Server response(encrypted): " + encryptedResponse);
            System.out.println("Server response(decrypted): " + decryptedResponse);
            System.out.println("-----------------------------------------------------------------------------");
            System.out.println("[Client] Valid server response received. Nonce matches.");
            System.out.println("-----------------------------------------------------------------------------");
            } else {
            System.out.println("MAC verification failed.");
            }
        } else {
        System.out.println("Invalid response format.");
        }
}


}
