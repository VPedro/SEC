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
	private RegisterReadMessage rcvRegisterReadMessage;
	private RegisterMessage rcvRegisterMessage;
	private SignedMessage rcvSignedMessage;
	private AckMessage respMsg;

	private int myID;


	ServerRequestThread(int id, RegisterThread register, RegisterReadMessage msg, int port) {
		this.myID = id;
		this.register = register;
		this.serverPort = port;
		this.rcvRegisterReadMessage = msg;
	}
	ServerRequestThread(int id, RegisterThread register, RegisterMessage msg, int port) {
		this.myID = id;
		this.register = register;
		this.serverPort = port;
		this.rcvRegisterMessage = msg;
	}
	ServerRequestThread(int id, RegisterThread register, SignedMessage msg, int port) {
		this.myID = id;
		this.register = register;
		this.serverPort = port;
		this.rcvSignedMessage = msg;
	}
	ServerRequestThread(int id, RegisterThread register, Message msg, int port) {
		this.myID = id;
		this.register = register;
		this.serverPort = port;
		this.rcvMessage = msg;
	}

	public void run() {
		Object responseMsg;

		try {
			server = new Socket("localhost",serverPort);
		} catch (IOException e1) {
			//e1.printStackTrace();
		}
		try {
			serverOutputStream = new ObjectOutputStream(server.getOutputStream());
			serverInputStream = new ObjectInputStream(server.getInputStream());

			if(rcvMessage != null){
				serverOutputStream.writeObject(rcvMessage);
			}else if(rcvRegisterReadMessage != null){
				serverOutputStream.writeObject(rcvRegisterReadMessage);
			}else if(rcvRegisterMessage != null){
				serverOutputStream.writeObject(rcvRegisterMessage);
			}else if(rcvSignedMessage != null){
				serverOutputStream.writeObject(rcvSignedMessage);
			}
			responseMsg = serverInputStream.readObject();

			
			if(responseMsg instanceof AckMessage){
				AckMessage resMsg= (AckMessage) responseMsg;
				resMsg.setID(this.myID);
				register.response((AckMessage) responseMsg);
			}
			else if(responseMsg instanceof SignedMessage){
				SignedMessage resMsg= (SignedMessage) responseMsg;
				resMsg.setID(this.myID);
				register.response((SignedMessage) responseMsg);
			}
			else if(responseMsg instanceof ReadResponseMessage){
				ReadResponseMessage resMsg= (ReadResponseMessage) responseMsg;
				resMsg.setID(this.myID);
				register.response(resMsg);
			}else if(responseMsg == null){
				System.out.println("NAO DEVE ENVIAR NULL");
				ReadResponseMessage r = null;
				register.response(r);
			}
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
		}
	}
}
