import java.io.*;
import java.net.Socket;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class UserInterface {
	
	// Text Color
	public static final String RESET = "\u001B[0m"; 
    public static final String BLUE = "\u001B[34m";   
    public static final String GREEN = "\u001B[32m";
    public static final String CYAN = "\u001B[36m";
    
    public static void main(String[] args) throws InterruptedException {
        final String SERVER_HOST = "localhost";
        final int SERVER_PORT = 6952;

        try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
             ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream());
             BufferedReader consoleReader = new BufferedReader(new InputStreamReader(System.in))) {
        	
        	String whichServer = (String) inputStream.readObject();
            System.out.println("Connected to the " + whichServer);

            if(whichServer.equals("TimeServer")) {
            	String currentTime = (String) inputStream.readObject();
                System.out.println("Server Response: " + BLUE + currentTime + RESET);
                
            }
            else {
            	// Client sends the username
                System.out.print("\nEnter your username: " + GREEN);
                String username = consoleReader.readLine();
                outputStream.writeObject(username);
                System.out.print(RESET);
                
                boolean flagUsername = (boolean) inputStream.readBoolean();
                if(flagUsername) {
                	String randomKey = (String) inputStream.readObject();

                    // Messages are coming from Authentication Server
                    String msg1 = (String) inputStream.readObject(); //session key between C-TGS
                    String msg2 = (String) inputStream.readObject(); //ticket
                    System.out.println(CYAN + "\nMessage from Authentication Server," + RESET + "\nReceived encrypted session key between client and TGS: " + BLUE + msg1 + RESET );
                    System.out.println("Received encrypted ticket: " + BLUE + msg2 + RESET);
                                   
                    // Client enters her/his password
                    System.out.print("\nEnter your password: " + GREEN);
                    Scanner s = new Scanner(System.in);
                    String inputPassword = s.nextLine();
                    System.out.print(RESET);
                    
                    String clientKey = encryptionFunc(inputPassword, randomKey);
                    
                    String sessionKey_C_TGS = decryptionFunc(msg1, clientKey); // session key between C-TGS is obtained
                	System.out.println("\nSession key between client and TGS is decrypted using client's key: " + BLUE + sessionKey_C_TGS + RESET);
                    
                	long currentTimeMillis = System.currentTimeMillis();
                	String encryptedMessage = username + ":" + String.valueOf(currentTimeMillis);
                	System.out.println("\nUsername and timeStamp information: " + BLUE + encryptedMessage + RESET);
                	String encryptedTime = encryptionFunc(encryptedMessage, sessionKey_C_TGS);
                	outputStream.writeObject(encryptedTime); // encrypted timeStamp information is sent to TGS.
                	System.out.println("Encrypted username and timeStamp information is sent to server: " + BLUE + encryptedTime +RESET);
                	
                	outputStream.writeObject(msg2); // ticket is sent to TGS
                	System.out.println("\nTicket is sent to server: " + BLUE + msg2 + RESET);
                	
                	// Messages from TGS
                	String msg3 = (String) inputStream.readObject(); // session key between C-Server
                    String msg4 = (String) inputStream.readObject(); // token
                    System.out.println(CYAN + "\nMessage from Ticket Granting Server," + RESET + "\nReceived encrypted session key between client and server: " + BLUE + msg3 + RESET);
                    System.out.println("Received encrypted token: " + BLUE + msg4 + RESET);
                	
                	String sessionKey_C_Server = decryptionFunc(msg3, sessionKey_C_TGS);
                	System.out.println("\nSession key between client and server is decrypted using sessionKey between client and server: " + BLUE + sessionKey_C_Server + RESET);
                            
                	long currentTimeMillis2 = System.currentTimeMillis();
                	String encryptedMessage2 = username + ":" + String.valueOf(currentTimeMillis2);
                	System.out.println("\nUsername and timeStamp information: " + BLUE + encryptedMessage2 + RESET);
                	String encryptedTime2 = encryptionFunc(encryptedMessage2, sessionKey_C_Server);
                	outputStream.writeObject(encryptedTime2); // encrypted timeStamp information is sent to TGS.
                	System.out.println("Encrypted username and timeStamp information is sent to server: " + BLUE + encryptedTime2 + RESET);
                	
                	outputStream.writeObject(msg4); // token is sent to server
                	System.out.println("\nToken is sent to server: " + BLUE + msg4 + RESET);
                	
                	System.out.print(CYAN + "\nMessage from Server," + RESET + BLUE);
                	String isAuth = (String) inputStream.readObject();
                	System.out.println(isAuth);
                	System.out.println(RESET);

                	
                	
                    // Check if she/he is the administrator or client
                    if(username.equals("nilhan")) {
                    	System.out.print("Do you want to update the server key? (yes/no): " + GREEN);
                        String keyUpdateChoice = consoleReader.readLine().toLowerCase();
                        outputStream.writeObject(keyUpdateChoice);
                        System.out.print(RESET);
                        
                        // Administrator requests to update the server key
                        if ("yes".equals(keyUpdateChoice)) {
                        	System.out.println("\nUpdating server key...");
                        	
                            
                            // SERVER SIDE !!!  System.out.println("Received new server key: " + newServerKey);
                            System.out.println("Server key update is completed.");                
                        }
                    }
                    else {
                    	System.out.print("\nNot allowed to update the server key.\nDo you want to update the client key? (yes/no): " + GREEN);
                        String keyUpdateChoice = consoleReader.readLine().toLowerCase();
                        outputStream.writeObject(keyUpdateChoice);
                        System.out.print(RESET);

                        // Client requests to update the client key
                        if ("yes".equals(keyUpdateChoice)) {
                        	System.out.println("\nUpdating client key...");
                        	String newClientKey = (String) inputStream.readObject();
                        	System.out.println("New Client's Key is received: " + BLUE + newClientKey + RESET);
                
                        }
                    }
                }            
                else {
                	String notValidUsername = (String) inputStream.readObject();
                	System.out.println(notValidUsername);
                }
            }
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
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
    
    private static String decryptionFunc(String message, String key) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.getBytes(), "AES"));
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(message));
            return new String(decryptedBytes);
        } catch (Exception e) {
        	System.err.println("Decryption process is failed! System is exitting...");
            System.exit(0);
            return null;
        }
    }
}
