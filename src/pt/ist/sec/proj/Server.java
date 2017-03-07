package pt.ist.sec.proj;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
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
	
	public static void	put(String domain, String username, String password){ 
		ArrayList<String> list = new ArrayList<String>(); list.add(domain); list.add(username);
		map.put(list, password);
	}
	
	public static String get(String domain, String username){
		ArrayList<String> list = new ArrayList<String>(); list.add(domain); list.add(username);
		return map.get(list);
	}
	
	
	
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
            
            while(true){
            	ObjectInputStream objIn = new ObjectInputStream(server.getInputStream());
            	try {
					Message m = (Message)objIn.readObject();
					switch(m.getFunctionName()) {
						case "save_password":
							put(m.getDomain(), m.getUsername(), m.getPassword());
							out.writeUTF("Password saved!");
							break;
						case "retrieve_password":
							out.writeUTF("Retrieving password");
							out.writeUTF(get(m.getDomain(), m.getUsername()));			
					}
				} catch (ClassNotFoundException e) {
					e.printStackTrace();
				}
            }
            
            
            //server.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
}
