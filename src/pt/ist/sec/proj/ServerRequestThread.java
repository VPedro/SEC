package pt.ist.sec.proj;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class ServerRequestThread extends Thread {

	private RegisterThread register;
	
	private ObjectInputStream serverInputStream;
	private ObjectOutputStream serverOutputStream;
	
	private Socket server;
	
	private int serverPort;
	private Message rcvMessage;
	private SignedMessage rcvSignedMessage;
	
	ServerRequestThread(RegisterThread register, Message msg, int port) {
		this.register = register;
		this.serverPort = port;
		this.rcvMessage = msg;
	}
	
	ServerRequestThread(RegisterThread register, SignedMessage msg, int port) {
		this.register = register;
		this.serverPort = port;
		this.rcvSignedMessage = msg;
	}
	
	public void run() {
		System.out.println("FIZ CENAS");
		Object responseMsg;
		
		try {
			server = new Socket("localhost",serverPort);
		} catch (IOException e1) {
			//e1.printStackTrace();
			
		}
		try {
			serverOutputStream = new ObjectOutputStream(server.getOutputStream());
			serverInputStream = new ObjectInputStream(server.getInputStream());
			
			if(rcvMessage!= null){
				serverOutputStream.writeObject(rcvMessage);
				
			}else if(rcvSignedMessage != null){
				serverOutputStream.writeObject(rcvSignedMessage);
			}
			
			responseMsg = serverInputStream.readObject();
			
			if(responseMsg instanceof SignedMessage)
				register.response((SignedMessage) responseMsg);
			else if(responseMsg instanceof Message)
				register.response((Message) responseMsg);
			
			
		} catch (IOException | ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		//resMsg = new SignedMessage(null,pubKey,sign_pub ,"register_fail", null, null, null);
		
			//resMsg = new SignedMessage(null,pubKey,sign_pub ,"register_fail", null, null, null);
		//	objOut.writeObject(resMsg);
		
	}
	
}
