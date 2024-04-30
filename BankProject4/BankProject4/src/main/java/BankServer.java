 /*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

/**
 *
 * @author ashikreji
 */
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;

/**
 *
 * @author Nabhanya Sharma
 */
class ClientHandler implements Runnable {
    static String MASTER_SECRET = "";
    private Socket clientSocket;
    private static final String PRE_SHARED_KEY = "mySecretPSK";
//private static final String MASTER_SECRET = "masterSecretKey";

    public ClientHandler(Socket socket) {
        this.clientSocket = socket;
    }

    public void run() {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

            String serializedPublicKey = serializePublicKey(BankServer.getPublicKey());
            out.println(serializedPublicKey);
            System.out.println("-----------------------------------------------------------------------------");
            System.out.println("[Server] Public key sent to the client.");
            System.out.println("-----------------------------------------------------------------------------");
    
            String receivedPSK = in.readLine();
            if (PRE_SHARED_KEY.equals(receivedPSK)) {
                System.out.println("-----------------------------------------------------------------------------");
                System.out.println("[Server] Pre-Shared Key verified. Authenticated the client.");
                System.out.println("-----------------------------------------------------------------------------");

                MASTER_SECRET = generateDynamicMasterSecret();
                out.println("AUTH_SUCCESS");
                String encryptedMasterSecret = BankServer.encryptMasterSecretWithPrivateKey(MASTER_SECRET);

                String encryptionKey = KeyDerivationUtil.deriveKey(MASTER_SECRET, "encryption");
                String macKey = KeyDerivationUtil.deriveKey(MASTER_SECRET, "mac");

                out.println(encryptedMasterSecret);
                System.out.println("-----------------------------------------------------------------------------");
                System.out.println("[Server] Master Secret encrypted with the server's private key and sent to the client.");
                System.out.println("-----------------------------------------------------------------------------");
                
                System.out.println("Server Encryption Key: " + encryptionKey);
                System.out.println("Server MAC Key: " + macKey);
                System.out.println("-----------------------------------------------------------------------------");
                System.out.println("[Server] Encryption and MAC keys derived from the Master Secret.");
                System.out.println("-----------------------------------------------------------------------------");
            } else {
                out.println("AUTH_FAILED");
                clientSocket.close();
                return;
            }
            int amount=0;
            String inputLine;
            while ((inputLine = in.readLine()) != null) {

                System.out.println("Raw message received: " + inputLine);
                String[] parts = inputLine.split("\\|");
                if (parts.length != 2) {
                    System.err.println("Invalid transaction format received. Expected nonce, encrypted data, and MAC.");
                    continue;
                }

                String encryptedTransaction = parts[0];
                String receivedMac = parts[1];
    
                System.out.println("Expected HMAC (server): " + receivedMac);
                
             
                try {
                    
                    if (CryptoUtil.verifyHmac(encryptedTransaction, MASTER_SECRET, receivedMac)) {
                           String decryptedTransaction = CryptoUtil.decrypt(encryptedTransaction, MASTER_SECRET);
                           String[] transactionParts = decryptedTransaction.split("\\|");
                           String transactionType = transactionParts[0];
                           String account = transactionParts[1];
                           String amountOrResponseMessage = ""; 
                           
                            System.out.println("-----------------------------------------------------------------------------");
                            System.out.println("[Server] Transaction MAC verified. Proceeding with transaction.");
                            System.out.println("-----------------------------------------------------------------------------");
            

                            System.out.println("Transaction type: " + transactionType);
                            System.out.println("Account number: " + account);
                            String nonce = transactionParts[transactionParts.length - 1]; 
                            System.out.println("Received Nonce: " + nonce);

//         didn't write any logic for each of the transactions just the encryption/decryption
//          so rn its just placeholders
                            switch (transactionType.toUpperCase()) {
                                case "DEPOSIT":
                                    
                                    amount=amount+Integer.valueOf(transactionParts[2]);
//                              processDeposit(account, transactionParts[2]);
                                    //processaudit
                                    amountOrResponseMessage = "Deposit successful: $"+amount;
//                                    rn this is empty
                                    break;
                                case "WITHDRAWAL":
//                                  processWithdrawal(account, transactionParts[2]);
//                                    rn this is empty
                                    amountOrResponseMessage="Not sufficient funds";
                                    if(amount>(Integer.valueOf(transactionParts[2]))){
                                    amount=amount-Integer.valueOf(transactionParts[2]);
                                    amountOrResponseMessage = "Withdrawal successful: $"+Integer.valueOf(transactionParts[2]);
                                    }
                                    ;
                                    break;
                                case "BALANCE":
//                                  String balance = getBalance(account);
//                                    rn this is empty                   
                                   
                                    amountOrResponseMessage = "Current balance: $" +amount;
                                    break;                                                              
                               
                                default:
                                    amountOrResponseMessage = "Unsupported transaction type";
                                    break;
                            }

            
                            sendEncryptedResponse(amountOrResponseMessage, nonce, out);
                            System.out.println("-----------------------------------------------------------------------------");
                            System.out.println("[Server] Sending encrypted response to the client, including the nonce for verification.");
                            System.out.println("-----------------------------------------------------------------------------");

            } else {
            System.err.println("MAC verification failed for transaction.");
        }
        } catch (Exception e) {
            System.err.println("Transaction processing error: " + e.getMessage());
        }
    }
             
            clientSocket.close();
             
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    private String serializePublicKey(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
}
    
    
    
    private String generateDynamicMasterSecret() {
        SecureRandom random = new SecureRandom();
        byte[] secretBytes = new byte[32];
        random.nextBytes(secretBytes);
        return Base64.getEncoder().encodeToString(secretBytes);
    }
    
    private void sendEncryptedResponse(String responseMessage, String nonce, PrintWriter out) throws Exception {
        String responseWithNonce = responseMessage + " | " + nonce; 
        String encryptedResponse = CryptoUtil.encrypt(responseWithNonce, MASTER_SECRET);
        String responseMac = CryptoUtil.generateHmac(encryptedResponse, MASTER_SECRET);
        out.println(encryptedResponse + "|" + responseMac);
    }
   
}

public class BankServer {
      private static PrivateKey privateKey;
    private static PublicKey publicKey;
    public static void main(String[] args) {
        int portNumber = 12345; 
        try {
            ServerSocket serverSocket = new ServerSocket(portNumber);
            generateKeyPair();
            System.out.println("Server started. Listening on port " + portNumber);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client connected: " + clientSocket);
                
                new Thread(new ClientHandler(clientSocket)).start();
            }
        } catch (IOException e) {
            System.err.println("Could not listen on port " + portNumber);
            e.printStackTrace();
        }
    }
        private static void generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048); 
            KeyPair pair = keyGen.generateKeyPair();
            privateKey = pair.getPrivate();
            publicKey = pair.getPublic();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
        
    public static PublicKey getPublicKey() {
        return publicKey;
    }
    
    public static String encryptMasterSecretWithPrivateKey(String secret) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            byte[] encryptedBytes = cipher.doFinal(secret.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null; 
        }
    }
    
}
