import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AuthTicketServer {
	
	// Text Color
	public static final String RESET = "\u001B[0m"; 
	public static final String BLUE = "\u001B[34m";   
	public static final String GREEN = "\u001B[32m";
	public static final String CYAN = "\u001B[36m";
	
	private static Map<String, String> userMap = new HashMap<>();
	private static Map<String, Ticket> ticketMap = new HashMap<>();
	private static String clientKey;
	private static String tgsKey;
	private static String serverKey;
	private static String randomKey;
	private static String sessionKey_C_TGS;
	private static String sessionKey_C_Server;
	
	private static final long TICKET_EXPIRATION_TIME = 3600 * 1000; // 1 hour

	public static void main(String[] args) {
		userMap.put("nilhan", "nilhan1234"); // administrator
		userMap.put("alice", "alice1234");
		userMap.put("bob", "bob1234");
		userMap.put("clara", "clara1234");
		userMap.put("tom", "tom1234");
		
		final int PORT = 6952;

        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Authentication and Ticket Server is running on port " + PORT);

            while (true) {
            	System.out.println("\nWaiting for client connections...");
                Socket clientSocket = serverSocket.accept();

                Thread clientHandler = new Thread(() -> handleClient(clientSocket));
                clientHandler.start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
	}
	
	private static void handleClient(Socket clientSocket) {
		try {
			System.out.println("Client connected: " + clientSocket.getInetAddress().getHostAddress());

            ObjectInputStream inputStream = new ObjectInputStream(clientSocket.getInputStream());
            ObjectOutputStream outputStream = new ObjectOutputStream(clientSocket.getOutputStream());

            // Indicator to prove that it's the AuthTicketServer
            outputStream.writeObject("Authentication&TicketServer");
            
            // Authentication server gets the username
            String username = (String) inputStream.readObject();
            
            boolean flagUsername;
            
            // Check if the username is valid
            if (checkUsername(username)) {
            	flagUsername = true;
            	outputStream.writeBoolean(flagUsername);
            	
            	randomKey = generateKey();
            	outputStream.writeObject(randomKey);
            	// Generate client, TGS and server keys
            	String password = userMap.get(username);
            	clientKey = encryptionFunc(password, randomKey);
            	tgsKey = generateKey();   	
            	serverKey= generateKey();
            	
            	System.out.println("\nUsername is received: " + BLUE + username +RESET);           	
            	System.out.println("\nClient Key: " + BLUE + clientKey + RESET);
            	System.out.println("TGS Key: " + BLUE + tgsKey + RESET);
            	System.out.println("Server Key: " + BLUE + serverKey + RESET);
            	
            	// Client sends username to Authentication Server 
            	System.out.println(CYAN + "\nIn Authentication Server," + RESET);
                String msg1 = authServerMsg1(username); // First message of AS -> session key encrypted with client's key
                String msg2 = authServerMsg2(username); // Second message of AS -> ticket (username, session key, exp_date)
                
                // These messages are sent to client.
                outputStream.writeObject(msg1);
                System.out.println("\nEncrypted Session key between client and TGS is sent to client: " + BLUE + msg1 + RESET);
                outputStream.writeObject(msg2);
                System.out.println("Encrypted Ticket is sent to client: " + BLUE + msg2 + RESET);
                
                // TGS gets the encrypted ticket and timestamp          
                String encryptedTime = (String) inputStream.readObject();
                System.out.println(CYAN + "\nIn Ticket Granting Server," + RESET);
                System.out.println("\nEncrypted username and timeStamp information is received: " + BLUE + encryptedTime + RESET);
                String ticket = (String) inputStream.readObject();
                System.out.println("Ticket is received: " + BLUE + ticket + RESET);
                
                // Decrypt the ticket to obtain session key between client and TGS
                String decryptedTicket = decryptionFunc(ticket, tgsKey); // username, sessionKey, exp_date are obtained
                System.out.println("\nTicket is decrypted using TGS Key: " + BLUE + decryptedTicket + RESET);
                String getSessionKey_C_TGS = extractValue(decryptedTicket, 3, 1);
                String getUsername1 = extractValue(decryptedTicket, 3, 0);
                System.out.println("Session key between client and TGS is obtained: " + BLUE + getSessionKey_C_TGS + RESET);
                
                // TimeStamp information is decrypted using session key between client and TGS
                String decryptedTime = decryptionFunc(encryptedTime, getSessionKey_C_TGS);         
                
                // Extract username and timestamp
                String getUsername2 = extractValue(decryptedTime, 2, 0);
                System.out.println("\nTimeStamp message is decrypted.\nObtained username: " + BLUE + getUsername2 + RESET);
                long getTimeStamp = Long.parseLong(extractValue(decryptedTime, 2, 1));
                System.out.println("Obtained timeStamp: " + BLUE + getTimeStamp + RESET);
                
                if(getUsername1.equals(getUsername2)) {
                	System.out.println("\nUsernames obtained from two encrypted messages are matched.");
                	if(checkTicketValidation(username, getTimeStamp)) {
                		String msg3 = tgsMsg1(username); // First message of TGS -> session key encrypted with session key between client and TGS
                        String msg4 = tgsMsg2(username); // Second message of TGS -> token (username, session key, exp_date)
                        
                        // These messages are sent to client.
                        outputStream.writeObject(msg3);
                        System.out.println("\nEncrypted Session key between client and server is sent to client: " + BLUE + msg3 + RESET);
                        outputStream.writeObject(msg4);
                        System.out.println("Encrypted Token is sent to client: " + BLUE + msg4 + RESET);
                                               
                        // Server gets the encrypted token and timestamp message            
                        String encryptedTime2 = (String) inputStream.readObject();
                        System.out.println(CYAN + "\nIn Server," + RESET);
                        System.out.println("\nEncrypted username and timeStamp information is received: " + BLUE + encryptedTime2 + RESET);
                        String token = (String) inputStream.readObject();
                        System.out.println("Token is received: " + BLUE + token + RESET);
                        
                        // Decrypt the token to obtain session key between client and server, and validity
                        String decryptedToken = decryptionFunc(token, serverKey); // username, sessionKey, exp_date are obtained
                        System.out.println("\nToken is decrypted using server's Key: " + BLUE + decryptedToken + RESET);
                        String getSessionKey_C_Server = extractValue(decryptedToken, 3, 1);
                        System.out.println("Session key between client and server is obtained: " + BLUE + getSessionKey_C_Server + RESET);
                        long getValidity = Long.parseLong(extractValue(decryptedToken, 3, 2));
                        System.out.println("Obtained validity from token: " + BLUE + getValidity + RESET); 
                        
                        // Decrypt "username+timestamp" message with session key between client and server
                        String decryptedMsg = decryptionFunc(encryptedTime2, getSessionKey_C_Server);
                        System.out.println("\nUsername and timestamp message is decrypted using sessionKey between client and server: " + BLUE + decryptedMsg + RESET); 
                        long getTimestamp = Long.parseLong(extractValue(decryptedMsg, 2, 1));
                        System.out.println("Obtained timeStamp from the decrypted message: " + BLUE + getTimestamp + RESET); 
                        
                        // Comparasion between timestamp and validation
                        if(getValidity >= getTimestamp) {
                        	System.out.println(CYAN + "\nValidation check is succesful!"+ RESET);
                        	outputStream.writeObject("\nClient successfuly authenticated!");
                        	
                        	String keyUpdateChoice = (String) inputStream.readObject();
                            if(username.equals("nilhan")) {
                            	if ("yes".equals(keyUpdateChoice.toLowerCase())) {
                                    System.out.println("\nAdministrator has requested to update the server key.");
                                    
                                    // A new server key is generated
                                    serverKey= generateKey();                      
                                    System.out.println("The server key is updated: " + BLUE + serverKey + RESET);
                                }                	
                            }
                            else {
                            	if ("yes".equals(keyUpdateChoice.toLowerCase())) {
                                    System.out.println("\nClient has requested to update the key.");
                                    
                                    // A new client key is generated
                                    clientKey = generateKey();         
                                    outputStream.writeObject(clientKey); // Server informs the client about updating the client key
                                    System.out.println("The client key is updated: " + BLUE + clientKey + RESET);
                                }
                            }
                        }                      	
                	}                	               	
                }
            }
            else {
            	flagUsername = false;
            	String notValidUsername = "\nUsername is not valid. Try again later.";
            	System.out.println(notValidUsername);
            	outputStream.writeObject(notValidUsername);
            }
            
        } catch (Exception e) {
        	System.err.println("\nSystem is exitting due to mismatch between passwords...");
        	System.exit(0);
        }
	}
	
	public static boolean checkTicketValidation(String username, long timeStamp) {
		for(java.util.Map.Entry<String, Ticket> entry: ticketMap.entrySet()) {
			if(entry.getKey().equals(username)) {
				Ticket getTicket = entry.getValue();
				long getExpirationTime = getTicket.getExpirationTime();
				if(getExpirationTime >= timeStamp) {
					System.out.println("\nExpiration time of the ticket is checked.\nThe ticket is valid.");
					return true;
				}
			}
		}    
		return false;
	}
	
	public static String extractValue(String input, int numOfObjects, int desiredPart) {
        String[] parts = input.split(":");      
        if (parts.length >= numOfObjects) {
            return parts[desiredPart];
        } else {
            return null; 
        }
    }
	
	public static String tgsMsg1(String username) {
		sessionKey_C_Server = generateKey();
		System.out.println("\nSession Key between client and server is created: " + BLUE + sessionKey_C_Server + RESET);
		System.out.println("Then, encrypted with session key between client and TGS: " + BLUE + encryptionFunc(sessionKey_C_Server, sessionKey_C_TGS) + RESET);
		return encryptionFunc(sessionKey_C_Server, sessionKey_C_TGS);
	}
	
	public static String tgsMsg2(String username) {
		long validity = System.currentTimeMillis() + TICKET_EXPIRATION_TIME;
		String token = ticketAndTokenGenerator(username, sessionKey_C_Server, validity);		
		System.out.println("\nToken is generated: " + BLUE + token + RESET);
		System.out.println("Then, encrypted with server's key " + BLUE + encryptionFunc(token, serverKey) + RESET);
		return encryptionFunc(token, serverKey);
	}
	
	
	public static String authServerMsg1(String username) {
		sessionKey_C_TGS = generateKey();
		System.out.println("\nSession Key between client and TGS is created: " + BLUE +  sessionKey_C_TGS + RESET);
		System.out.println("Then, encrypted with clientKey: " + BLUE + encryptionFunc(sessionKey_C_TGS, clientKey) + RESET);
		return encryptionFunc(sessionKey_C_TGS, clientKey);
	}
	
	public static String authServerMsg2(String username) {
		long validity = System.currentTimeMillis() + TICKET_EXPIRATION_TIME;
		String ticket = ticketAndTokenGenerator(username, sessionKey_C_TGS, validity);
		ticketMap.put(username, new Ticket(username, sessionKey_C_TGS, validity));
		System.out.println("\nTicket is generated: " + BLUE + ticket + RESET);
		System.out.println("Then, encrypted with TGS Key: " + BLUE + encryptionFunc(ticket, tgsKey) + RESET);
		return encryptionFunc(ticket, tgsKey);
	}
	
	public static String ticketAndTokenGenerator(String username, String sessionKey, long validity) {
		String t_generated = username + ":" + sessionKey + ":" + validity;
		return t_generated;
	}
	
	private static String decryptionFunc(String message, String key) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.getBytes(), "AES"));
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(message));
            return new String(decryptedBytes);
        } catch (Exception e) {
            System.err.println("Decryption process is failed! System is exitting...");
            return null;
        }
    }
	
	public static String encryptionFunc(String message, String key) {
		try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getBytes(), "AES"));
            byte[] encryptedBytes = cipher.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
	}
	
	public static String generateKey() {
        String algorithm = "AES";
        int keyLength = 128;

        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
            keyGen.init(keyLength);
            SecretKey secretKey = keyGen.generateKey();
            return bytesToBase64(secretKey.getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
	
	private static String bytesToBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }
	
	public static boolean checkUsername(String username) {
		for(java.util.Map.Entry<String, String> entry: userMap.entrySet()) {
			if(entry.getKey().equals(username)) {
				return true;
			}
		}
		return false;
	}
	
}
