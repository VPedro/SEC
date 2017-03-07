package pt.ist.sec.proj;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.*;

public class Server {

	private static ServerSocket serverSocket;
	private static Map<ArrayList<String>, String> map;
	
	public static void main(String args[]){
		map = new HashMap<ArrayList<String>, String>();
		
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
