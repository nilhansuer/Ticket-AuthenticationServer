import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.text.SimpleDateFormat;
import java.util.Date;

public class TimeServer {

    public static void main(String[] args) {
        final int PORT = 8925;

        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Time Server is running on port " + PORT);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                
                // To handle multiple clients concurrently -> THREAD
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

            ObjectOutputStream outputStream = new ObjectOutputStream(clientSocket.getOutputStream());
            
            // Indicator to prove that it's the TimeServer
            outputStream.writeObject("TimeServer");
            
            String currentTime = getCurrentTime();
            outputStream.writeObject(currentTime);
            System.out.println("\nCurrent time information was sent to the client.");   

            clientSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static String getCurrentTime() {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        return dateFormat.format(new Date());
    }
}
