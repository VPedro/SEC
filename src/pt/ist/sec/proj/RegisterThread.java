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

	
	static boolean verbose = true;
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
		System.out.println("FIZ CENAS");

		crypto = new Crypto();
		Object input;
		try {
			objIn = new ObjectInputStream(librarysocket.getInputStream());
			objOut = new ObjectOutputStream(librarysocket.getOutputStream());
			System.out.println("streams ok");
			
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
				count = 0;
				
				finished=false;
				
				SignedMessage resSignedMsg;
				if (input instanceof SignedMessage) {

					SignedMessage m = (SignedMessage)input;

					if(m.getFunc().equals("register")){	

						for(int i = initialServerPort ; i<initialServerPort+numServers; i++){
							threads[i-initialServerPort] = new ServerRequestThread(this,m,i);
							threads[i-initialServerPort].start();
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
								System.out.println("GONNA SEND MY N0NCE");
							
								System.out.println(resSignedMsg.getSignNonce());
								System.out.println(resSignedMsg.getPubKey());
								System.out.println(resSignedMsg.getNonce());
							}
							
							try {
								objOut.writeObject(resSignedMsg);
							} catch (IOException e) {
								System.out.println("Error sending SignedMessage ");
							}
							
						}else{
							sendSignedMessage("nonce", pubKey, sign_pub, "fail", null);
						}
						//new ServerRequestThread(this,m,initialServerPort).start();
						
						/*for(int i = initialServerPort ; i<initialServerPort+numServers; i++){
							threads[i-initialServerPort] = new ServerRequestThread(this,m,i);
							threads[i-initialServerPort].start();
						}*/
						
						
					}	
				}
				else if(input instanceof Message) {
					Message m = (Message)input;

					if(m.getFunctionName().equals("save_password")){	
						if(validMessageSignatures(m,true,true,true,true)){
							if(verbose) {
								
								System.out.println("Expected nonce: " + register.getNonce(m.getPublicKey()));
								System.out.println("Nonce received from library: " + m.getNonce());
								
							}
							//Long n_compare = server.getNonces().get(m.getPublicKey());
							//FIXME compare nonces
							/*if((long)n_compare != ((long)m.getNonce())){
								System.out.println("Different Nonce, reject"); 
								sendSignedMessage("invalid", pubKey, sign_pub, "invalid message", null);
								continue; 
							}*/
							//System.out.println("DUP Signature verified successfully! (no yet...)");
							int tempWTS = register.getWTS();
							byte[] signWTS = crypto.signature_generate(intToBytes(tempWTS), privKey);
							
							//cada getNonce recebido manda pedido para srrver e ghuarda em nonces[numServers]
							//dentro do for para mandar o nonce respectivo
							
							//fazer as nossa signs
							byte[] signDom = crypto.signature_generate(m.getDomain(), privKey);
							byte[] signUser = crypto.signature_generate(m.getUsername(), privKey);
							byte[] signPass = crypto.signature_generate(m.getPassword(), privKey);
							
							RegisterMessage msg = new RegisterMessage("save_password", pubKey, sign_pub, tempWTS, signWTS, 
									m.getDomain(),signDom, m.getUsername(), signUser, m.getPassword(), signPass,null, null);

							for(int i = initialServerPort ; i<initialServerPort+numServers; i++){
								//get nonce
								//sign_nonce
								//criar msg aqui com nonce e sign respectivo
								threads[i-initialServerPort] = new ServerRequestThread(this,msg,i);
								threads[i-initialServerPort].start();
							}
						} else {
							System.out.println("Signature not valid!");
							//sendSignedMessage();
							//sendRegisterMessage("save_password", pubKey, sign_pub, "fail", null);
						}					
					}
					
					else if(m.getFunctionName().equals("retrieve_password")){	
						
						/*for(int i = initialServerPort ; i<initialServerPort+numServers; i++){
							System.out.println("retrieve pass to server :" + i);
							new ServerRequestThread(this,m,i).start();
						}	*/					
					}


				}
			} catch (ClassNotFoundException | IOException e) {
				System.out.println("Thread killed");
				connectionOpen = false;
			}
		}
	}
	
	public void response(AckMessage msg){
		count++;
		if(count > (numServers/2)){
			System.out.println("thread sends to lybrary saved with success");
			sendSignedMessage("save_password", pubKey, sign_pub, "success", null);
			count = 0;
		}
	}
	
	public void response(Message msg){
		if(msg.getFunctionName().equals("retrieve_password")){
			try {
				
				String end = endThread(new String(msg.getPassword()));
				if(end == null){
					return;
				}
				
				System.out.println("thread sends to lybrary " + new String(msg.getPassword()));
				objOut.writeObject(msg);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
	}
	

	public void response(SignedMessage msg){

		//ver se e maioria ou espera por mais responses!
		//if registeer nada
		
		System.out.println("response: " + msg.getRes());

		if(msg.getFunc().equals("invalid")){
			try {
				//todo ver se maioria deu invalid
				System.out.println("invalid msg");
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
				
				System.out.println("thread sends to lybrary " + msg.getRes());
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
				
				System.out.println("thread sends to lybrary: " + msg.getRes());
				objOut.writeObject(msg);
				
				
			} catch (IOException e) {
				// TODO Auto-generated catch block
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
			//valid4 = crypto.signature_verify(m.getSig_nonce(), m.getPublicKey(), m.getNonce().toString().getBytes());
			valid4=true;
		}
		//FIXME
		
		return valid1 & valid2 & valid3 & valid4 ;
	}
	
	public byte[] intToBytes( final int i ) {
	    ByteBuffer bb = ByteBuffer.allocate(4); 
	    bb.putInt(i); 
	    return bb.array();
	}

	private String endThread(String res) {
		// TODO Auto-generated method stub
		resAnswers[count] = res;
		count++;
		
		String response = majority(resAnswers);
		if(response!=null){
			return response;
		}
		System.out.println("endthread result:" + response);
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
		System.out.println("saved nonce");
		return true;
	}
}
