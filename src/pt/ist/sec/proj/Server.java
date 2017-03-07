package pt.ist.sec.proj;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import javax.crypto.*;
public class Server {

	private static ServerSocket serverSocket;
	
	public static void main(String args[]){
		System.out.println("SERVER STARTING");
		try {
			serverSocket = new ServerSocket(85);
			Socket server = serverSocket.accept();
			
			DataInputStream in = new DataInputStream(server.getInputStream());
            
            System.out.println(in.readUTF());
            DataOutputStream out = new DataOutputStream(server.getOutputStream());
            out.writeUTF("Goodbye!");
            server.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
}
