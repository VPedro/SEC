package pt.ist.sec.proj;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;

public class ServerThread extends Thread {

	private Socket socket;
	private Server server;
	
	static PublicKey pubKey;
	static PrivateKey privKey;

	public ServerThread(Socket clientSocket, Server server) {
		this.socket = clientSocket;
		this.server = server;
	}

	public void run() {
		ObjectInputStream objIn = null;
		ObjectOutputStream objOut = null;
		Crypto crypto = new Crypto();
		try {
			objIn = new ObjectInputStream(socket.getInputStream());
			objOut = new ObjectOutputStream(socket.getOutputStream());
		} catch (IOException e) {
			System.out.println("IOException");;
		}
		Object input;
		//FIXME change name to connectionOpen
		boolean var = true;
		boolean ver_d, ver_u, ver_p;
		while (var) {
			try {
				ver_d = true;
				ver_u = true;
				ver_p = true;
				input = objIn.readObject();
				if (input instanceof Message) {
					Message m = (Message)input;
					if(m.getFunctionName().equals("save_password")){
						ver_d = crypto.signature_verify(m.getSig_domain(), m.getPublicKey(), m.getDomain());
						ver_u = crypto.signature_verify(m.getSig_username(), m.getPublicKey(), m.getUsername());
						ver_p = crypto.signature_verify(m.getSig_password(), m.getPublicKey(), m.getPassword());
						if(ver_d && ver_u && ver_p){
							System.out.println("Signature verified successfully!");
							server.put(m.getPublicKey(), m.getDomain(), m.getUsername(), m.getPassword());
						}
						else {
							System.out.println("Signature not valid!");
						}
					}
					else if(m.getFunctionName().equals("retrieve_password")){
						ver_d = crypto.signature_verify(m.getSig_domain(), m.getPublicKey(), m.getDomain());
						ver_u = crypto.signature_verify(m.getSig_username(), m.getPublicKey(), m.getUsername());
						if(ver_d && ver_u) {
							System.out.println("Signature verified successfully!");
							byte[] pass = server.get(m.getPublicKey(), m.getDomain(), m.getUsername());
							Message m2 = new Message(null, null, null, null, pass, null, null, pass);
							objOut.writeObject(m2);
						}
						else {
							System.out.println("Signature not valid!");
						}
					}
				}
				else if(input instanceof SignedMessage) {
					SignedMessage m = (SignedMessage)input;

					if(m.getFunc().equals("register")){
						if(server.register(m)){
							//FIXME
							//faz sentido?? acho q sim mas ja é tarde
							boolean valid = crypto.signature_verify(m.getSign(), m.getPubKey(), m.getPubKey().getEncoded());
							
							if(valid) {
								System.out.println("Signature verified successfully!");
								//FIXME add sign for server?
								SignedMessage m2 = new SignedMessage(null, null, null, "Regitered with success");
								objOut.writeObject(m2);
							}
							
							//Message2 m2 = new Message2("register",null,res);
							//objOut.writeObject(resMsg);
							
							//return (String func, PublicKey pubKey, byte[] sign, String res) 
						}else{
							//FIXME propagar exceptions do server.register(m)  para aqui e dependendo do catch mandamos uma msg diferente
							SignedMessage resMsg = new SignedMessage(null,null,null ,"Fail for some reason");
						}
						
					}else if(m.getFunc().equals("nounce")){
						Long nounce= server.getNounce();
						if(nounce != 0){
							boolean valid = crypto.signature_verify(m.getSign(), m.getPubKey(), m.getPubKey().getEncoded());
							
							if(valid) {
								System.out.println("Signature verified successfully!");
								System.out.println("generated nounce: "+ nounce.toString());
								
								//FIXME add sign for server?
								SignedMessage m2 = new SignedMessage(null, null, null, nounce.toString());
								objOut.writeObject(m2);
							}
						
						}else{
							//FIXME propagar exceptions do server.register(m)  para aqui e dependendo do catch mandamos uma msg diferente
							SignedMessage resMsg = new SignedMessage(null,null,null ,"Fail for some reason");
						}
						
					}
					else if(m.getFunc().equals("close")){
						Message2 m2 = new Message2("close", null, "Closing");
						objOut.writeObject(m2);
						var = false;
						server.close();	
						//return;
					}
				}else if(input instanceof Message2) {
					Message2 m = (Message2)input;
					if(m.getFunc().equals("close")){
						Message2 m2 = new Message2("close", null, "Closing");
						objOut.writeObject(m2);
						var = false;
						server.close();	
						//return;
					}
				}/*else if(input==null){
					server.close();
				}*/
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
			} catch (EOFException e) {
				//e.printStackTrace();
				System.out.println("Exiting"); //FIXME
				var = false;
				//System.exit(0);
			} catch (IOException e) {
				System.out.println("IOException");
				e.printStackTrace();
			}
		}
	}

}
