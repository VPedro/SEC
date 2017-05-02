package pt.ist.sec.proj;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
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

	
	static boolean verbose = true;
	static int initialServerPort = 1026;
	static int numServers = 3;


	private ObjectInputStream objIn;
	private ObjectOutputStream objOut;

	//mudar para 
	String[] resAnswers;
	int count;
	static boolean finished;
	
	/*private Socket[] clients;
	ObjectOutputStream[] outObject;
	ObjectInputStream[] inObject;
	DataOutputStream[] outData;
	DataInputStream[] inData;*/



	RegisterThread(Socket socket, Register register) {
		this.librarysocket = socket;
		this.register = register;
	}

	public void run() {
		System.out.println("FIZ CENAS");

		Object input;
		try {
			objIn = new ObjectInputStream(librarysocket.getInputStream());
			objOut = new ObjectOutputStream(librarysocket.getOutputStream());
			System.out.println("streams ok");
			
			threads = new ServerRequestThread[numServers];

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
				if (input instanceof SignedMessage) {

					SignedMessage m = (SignedMessage)input;

					if(m.getFunc().equals("register")){	

						for(int i = initialServerPort ; i<initialServerPort+numServers; i++){
							threads[i-initialServerPort] = new ServerRequestThread(this,m,i);
							threads[i-initialServerPort].start();
						}						
					}else if(m.getFunc().equals("nonce")){	

						//pedir um nonce e atualizar os outros
						new ServerRequestThread(this,m,initialServerPort).start();
						
						/*for(int i = initialServerPort ; i<initialServerPort+numServers; i++){
							threads[i-initialServerPort] = new ServerRequestThread(this,m,i);
							threads[i-initialServerPort].start();
						}*/
						
						
					}	
				}
				else if(input instanceof Message) {
					Message m = (Message)input;

					if(m.getFunctionName().equals("save_password")){	
						
						for(int i = initialServerPort ; i<initialServerPort+numServers; i++){
							System.out.println("save pass to server :" + i);
							new ServerRequestThread(this,m,i).start();
						}						
					}	


				}
			} catch (ClassNotFoundException | IOException e) {
				System.out.println("Thread killed");
				connectionOpen = false;
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
			try {
				register.saveNonce(msg.getPubKey(),msg.getNonce(), msg.getSignNonce());
				count++;
				
				if(count==numServers){
					System.out.println("thread sends to lybrary " + msg.getRes());
					msg.setNonce(register.getExpectedNonce(msg.getPubKey()));
					objOut.writeObject(msg);
				}
				
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

	}
	
	private void interruptAll() {
		// TODO Auto-generated method stub
		for(Thread t:threads){
			if(!t.isInterrupted()){
				t.interrupt();
			}
		}
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
