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
			
			//DataInputStream in = new DataInputStream(server.getInputStream());
			DataOutputStream out = new DataOutputStream(server.getOutputStream());
			//System.out.println(in.readUTF());
            //out.writeUTF("Goodbye!");
			ObjectInputStream objIn = new ObjectInputStream(server.getInputStream());
           // while(true){
            	try {
					Message m = (Message)objIn.readObject();
					if(m.getFunctionName().equals("save_password")){
						System.out.println("Save_password received: " + m.getDomain() + ", " + m.getUsername() + ", " + m.getPassword());
						put(m.getDomain(), m.getUsername(), m.getPassword());
						out.writeUTF("Password saved!");
					}
					else if(m.getFunctionName().equals("retrieve_password")){
						System.out.println("Retrieve_password received: " + m.getDomain() + ", " + m.getUsername());
						out.writeUTF("Retrieving password... " + get(m.getDomain(), m.getUsername())); 
					}
				} catch (ClassNotFoundException e) {
					e.printStackTrace();
				}
           // }
            
            
            //server.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
}
