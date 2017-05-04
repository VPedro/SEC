package pt.ist.sec.proj;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RegisterThread extends Thread {

	private Socket librarysocket = null;
	private Register register;
	private int serverPort;
	private ServerRequestThread[] threads;
	private int regID;
	private String[] readList;


	static boolean verbose = false;
	static int initialServerPort = 1026;
	static int numServers;

	static PublicKey pubKey;
	static PrivateKey privKey;
	byte[] sign_pub;

	private ObjectInputStream objIn;
	private ObjectOutputStream objOut;

	//mudar para 
	String[] resAnswers;
	int count;
	static boolean finished;

	Crypto crypto;

	/*private Socket[] clients;
	ObjectOutputStream[] outObject;
	ObjectInputStream[] inObject;
	DataOutputStream[] outData;
	DataInputStream[] inData;*/



	RegisterThread(int regID,int numServer, Socket socket, Register register) {
		this.regID = regID;
		this.librarysocket = socket;
		this.register = register;
		this.numServers = numServer;
	}

	public void run() {
		crypto = new Crypto();
		Object input;
		try {
			objIn = new ObjectInputStream(librarysocket.getInputStream());
			objOut = new ObjectOutputStream(librarysocket.getOutputStream());

			threads = new ServerRequestThread[numServers];

			pubKey = register.getPubKey();
			privKey = register.getPrivKey();
			sign_pub = crypto.signature_generate(pubKey.getEncoded(), privKey);

		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}



		boolean connectionOpen = true;
		while (connectionOpen) {
			try {
				input = objIn.readObject();
				resAnswers = new String[numServers];
				//FIXME fazer array read/acks/ outro qlq?
				count = 0;

				finished=false;

				SignedMessage resSignedMsg;
				if (input instanceof SignedMessage) {

					SignedMessage m = (SignedMessage)input;

					if(m.getFunc().equals("register")){	

						for(int i = initialServerPort ; i<initialServerPort+numServers; i++){
							int id = i-initialServerPort;
							threads[id] = new ServerRequestThread(id,this,m,i);
							threads[id].start();
						}						
					}else if(m.getFunc().equals("nonce")){	
						register.setNonce(m.getPubKey());
						Long newNonce = register.getNonce(m.getPubKey());
						if(verbose) {
							System.out.println("Genereated nonce: " + newNonce);
						}
						if(newNonce != 0){
							byte[] sign_Nonce = crypto.signature_generate(newNonce.toString().getBytes("UTF-8"), privKey);
							resSignedMsg = new SignedMessage("nonce",pubKey,sign_pub, "success", null, newNonce, sign_Nonce);
							if(verbose){
								System.out.println(resSignedMsg.getSignNonce());
							}

							//reply our nonce to library
							try {
								objOut.writeObject(resSignedMsg);
							} catch (IOException e) {
								System.out.println("Error sending SignedMessage ");
							}

						}else{
							sendSignedMessage("nonce", pubKey, sign_pub, "fail", null);
						}
					}	
				}
				else if(input instanceof Message) {
					Message m = (Message)input;

					//fazer as nossa signs
					byte[] signDom = crypto.signature_generate(m.getDomain(), privKey);
					byte[] signUser = crypto.signature_generate(m.getUsername(), privKey);

					if(m.getFunctionName().equals("save_password")){	
						if(validMessageSignatures(m,true,true,true,true)){
							if(verbose) {
								System.out.println("Expected nonce: " + register.getNonce(m.getPublicKey()));
								System.out.println("Nonce received from library: " + m.getNonce());
							}
							int tempWTS = register.getWTS();
							byte[] signWTS = crypto.signature_generate(intToBytes(tempWTS), privKey);
							byte[] signPass = crypto.signature_generate(m.getPassword(), privKey);

							RegisterMessage msg = new RegisterMessage("save_password", pubKey, sign_pub, tempWTS, signWTS, 
									m.getDomain(),signDom, m.getUsername(), signUser, m.getPassword(), signPass,null, null, m.getPublicKey());

							for(int i = initialServerPort ; i<initialServerPort+numServers; i++){
								//get nonce,sign_nonce,criar msg aqui com nonce e sign respectivo
								//mas nao e preciso nonces
								int id = i-initialServerPort;
								threads[id] = new ServerRequestThread(id,this,msg,i);
								threads[id].start();

							}
						} else {
							System.out.println("Signature not valid!");
							//sendSignedMessage();
							//sendRegisterMessage("save_password", pubKey, sign_pub, "fail", null);
						}					
					}

					else if(m.getFunctionName().equals("retrieve_password")){	

						readList = new String[numServers];

						int tempRID = register.getRID();
						byte[] signRID = crypto.signature_generate(intToBytes(tempRID), privKey);
						RegisterReadMessage msg = new RegisterReadMessage(pubKey, sign_pub, tempRID, signRID, m.getPublicKey(), m.getDomain(), m.getSig_domain(), m.getUsername(), m.getSig_username());

						for(int i = initialServerPort ; i<initialServerPort+numServers; i++){
							System.out.println("Retrieve pass to server: " + i);
							int id = i-initialServerPort;
							threads[id] = new ServerRequestThread(id,this,msg,i);
							threads[id].start();
						}							
					}
				}
			} catch (ClassNotFoundException | IOException e) {
				System.out.println("Thread killed");
				connectionOpen = false;
			}
		}
	}

	public void response(AckMessage msg){
		count++;  //TODO meter lista de acks
		if(count > (numServers/2)){
			sendSignedMessage("save_password", pubKey, sign_pub, "success", null);
			count = 0;
		}
	}

	public void response(ReadResponseMessage msg){
		String end = endThread(new String(msg.getPassword()));
		if(end == null){
			return;
		}
		Message m2 = new Message(null, pubKey, null, null, crypto.signature_generate(msg.getPassword(), privKey), null, null, msg.getPassword(), null, null);
		//sendSignedMessage("retrieve_password", pubKey, sign_pub, end, null);
		try {
			objOut.writeObject(m2);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}


	//FIXME so dar erro uma vez caso msg.getRes for maioria
	public void response(SignedMessage msg){
		System.out.println("Response from serverRequestThread: " + msg.getRes());

		if(msg.getFunc().equals("invalid")){
			try {
				System.out.println("Invalid message");
				String end = endThread("invalid");
				if(end == null){
					return;
				}
				objOut.writeObject(msg);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		else if(msg.getFunc().equals("register")){

			try {
				String end = endThread(msg.getRes());
				if(end == null){
					return;
				}
				objOut.writeObject(msg);


			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		else if(msg.getFunc().equals("nonce")){
			register.setNonce(msg.getPubKey());
		}

		else if(msg.getFunc().equals("save_password")){
			try {
				String end = endThread(msg.getRes());
				if(end == null){
					return;
				}
				objOut.writeObject(msg);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		//em caso de erro "register_fail" ou "invalid message"
		else if(msg.getFunc().equals("retrieve_password")){
			//
			if(msg.getRes().equals("no password")){
				try {
					String end = endThread(msg.getRes());
					if(end == null){
						return;
					}
					objOut.writeObject(msg);				
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			try {
				String end = endThread(msg.getRes());
				if(end == null){
					return;
				}
				objOut.writeObject(msg);				
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	public void sendSignedMessage(String func, PublicKey pubKey, byte[] sign, String res, byte[] value){
		SignedMessage msg = new SignedMessage(func,pubKey, sign, res, value, null, null);
		try {
			objOut.writeObject(msg);
		} catch (IOException e) {
			System.out.println("Error sending SignedMessage ");
		}
	}


	public boolean validMessageSignatures(Message m, boolean dom, boolean user, boolean pass, boolean nonce){
		boolean valid1,valid2,valid3,valid4;
		valid1=valid2=valid3=valid4= true;

		if(dom){
			valid1 = crypto.signature_verify(m.getSig_domain(), m.getPublicKey(), m.getDomain());
		}
		if(user){
			valid2 = crypto.signature_verify(m.getSig_username(), m.getPublicKey(), m.getUsername());
		}
		if(pass){
			valid3 = crypto.signature_verify(m.getSig_password(), m.getPublicKey(), m.getPassword());
		}
		if(nonce){
			//TODO
			//valid4 = crypto.signature_verify(m.getSig_nonce(), m.getPublicKey(), m.getNonce().toString().getBytes());
			valid4=true;
		}
		return valid1 & valid2 & valid3 & valid4 ;
	}

	public byte[] intToBytes( final int i ) {
		ByteBuffer bb = ByteBuffer.allocate(4); 
		bb.putInt(i); 
		return bb.array();
	}

	private String endThread(String res) {
		if(finished)
			return null;

		resAnswers[count] = res;
		count++;

		String response = majority(resAnswers);
		if(response!=null){
			return response;
		}
		if(verbose) {
			System.out.println("Endthread result:" + response);
		}
		return null;
	}

	public static String majority(String[] answers) {
		Map<String, Integer> count = new HashMap<String, Integer>();
		for (String s : answers) {
			if (count.containsKey(s)) {
				count.put(s, count.get(s) + 1);
			} else {
				count.put(s, 1);
			}
		}
		String majority = null;
		for (String key : count.keySet()) {
			if (count.get(key) > numServers / 2) {
				majority = key;
			}
		}
		if(majority!=null && !finished){
			finished=true;
			return majority;
		}
		return null;
	}

	public boolean saveNounce(long nonce){
		return true;
	}
}
