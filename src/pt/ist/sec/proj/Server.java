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
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.*;

public class Server {

	private ServerSocket serverSocket;
	private Map<ArrayList<byte[]>, byte[]> map;
	
	public void printMap(){
		for(ArrayList<byte[]> a : this.map.keySet()){
			System.out.println(a.get(0) + ", " + a.get(1) + " = " + get(a.get(0), a.get(1)));		
		}
	}
	
	public void put(byte[] domain, byte[] username, byte[] password){ 
		ArrayList<byte[]> list = new ArrayList<byte[]>(); list.add(domain); list.add(username);
		map.put(list, password);
	}
	
	public byte[] get(byte[] domain, byte[] username){
		ArrayList<byte[]> list = new ArrayList<byte[]>(); list.add(domain); list.add(username);
		return map.get(list);
	}
	
	
	
	public static void main(String args[]){
		
		Server server = new Server();
		server.map = new HashMap<ArrayList<byte[]>, byte[]>();
		
		System.out.println("SERVER STARTING");
		try {

			server.serverSocket = new ServerSocket(1025);

			Socket serverClient = server.serverSocket.accept();
			
			//DataInputStream in = new DataInputStream(server.getInputStream());
			DataOutputStream out = new DataOutputStream(serverClient.getOutputStream());
			//System.out.println(in.readUTF());
            //out.writeUTF("Goodbye!");
			ObjectInputStream objIn = new ObjectInputStream(serverClient.getInputStream());
			ObjectOutputStream objOut = new ObjectOutputStream(serverClient.getOutputStream());
            while(true){
            	try {
					Message m = (Message)objIn.readObject();
					if(m.getFunctionName().equals("save_password")){
						System.out.println("Save_password received: " + Arrays.toString(m.getDomain()) + ", " + Arrays.toString(m.getUsername()) + ", " + Arrays.toString(m.getPassword()));
						server.put(m.getDomain(), m.getUsername(), m.getPassword());
						//out.writeUTF("Password saved!");
						out.writeBoolean(true);
					}
					else if(m.getFunctionName().equals("retrieve_password")){
						System.out.println("Retrieve_password received: " + Arrays.toString(m.getDomain()) + ", " + Arrays.toString(m.getUsername()));
						byte[] pass = server.get(m.getDomain(), m.getUsername());
						System.out.println("BYTEEEE");
						out.writeBoolean(true);
						server.printMap();
						System.out.println(m.getDomain() + " " + m.getUsername());
						System.out.println(pass);
						Message m2 = new Message(null, null, null, pass);
						System.out.println("CENAS");
						objOut.writeObject(m2);
						System.out.println("MANDEI");
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
