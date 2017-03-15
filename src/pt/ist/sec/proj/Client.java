package pt.ist.sec.proj;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.SocketException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class Client {

	public void menu(){
		System.out.println(" ");
		System.out.println("\t1 - Init");
		System.out.println("\t2 - Register");
		System.out.println("\t3 - Save password");
		System.out.println("\t4 - Retrieve password");
		System.out.println("\t5 - Close");
		System.out.println(" ");
		System.out.print("Choose an option: " );
	}

	public KeyStore getKeyStore(String pass){ //created with "olaola" as password
		KeyStore ks = null;
		try { //If KeyStore file already exists
			FileInputStream fis = new FileInputStream("keystorefile.jce");	//Open the KeyStore file
			ks = KeyStore.getInstance("JCEKS"); //Create an instance of KeyStore of type “JCEKS”
			ks.load(fis, pass.toCharArray()); //Load the key entries from the file into the KeyStore object.
			fis.close();
			System.out.println("KeyStore Loaded");
		} catch (FileNotFoundException e) {	
			try { //Could not load KeyStore file, create one
				ks = KeyStore.getInstance("JCEKS");
				ks.load(null, pass.toCharArray()); // Create keystore 
				//Create a new file to store the KeyStore object
				java.io.FileOutputStream fos = new java.io.FileOutputStream("keystorefile.jce");
				ks.store(fos, pass.toCharArray());
				//Write the KeyStore into the file
				fos.close();
				System.out.println("KeyStore Created");
			} catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException e1) {
				e1.printStackTrace();
			} 
		} catch (NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
			e.printStackTrace();
			ks = null;
		} catch (IOException e){
			ks = null;
		}
		return ks;
	}

	public static void main(String args[]){
		Client c = new Client();
		Library l = new Library();
		Scanner s = new Scanner(System.in);
		int option = 0;
		boolean initiated = false;
		String input;
		String[] spl;
		System.out.println(" ");
		System.out.println("===== Client Started =====");
		boolean var = true;
		while(var){
			c.menu();
			while(!s.hasNextInt()) {
				s.next();
				System.out.println(" ");
				System.out.println("Invalid Input");
				c.menu();
			}
			option = s.nextInt();
			System.out.println(" ");
			switch(option){
			//INIT
			case 1:
				if(initiated){
					System.err.println("you have already executed init");
					continue;
				}
				System.out.println("Login to your KeyStore:\n\"Username Password\"");
				s.nextLine();
				input = s.nextLine();
				spl = input.split(" ");
				if(spl.length != 2){
					System.err.println("2 parameters expected");
					continue;
				}
				//fix bug, 1 olaola exists, so... 2 olaola devia dar erro e nao dar loadKeys
				
				
				//if only one alias per file, change username to alias
				KeyStore ks = c.getKeyStore(spl[1]);
				if(ks==null){
					System.err.println("login invalid, try again");
					continue;
				}
				if(l.init(ks, spl[0], spl[1]))
					initiated =true;
				break;
			//REGISTER
			case 2:
				if(!initiated){
					System.err.println("you need to call init in order to contact server");
					continue;
				}
				if(l.register_user()){
					System.out.println("Registered with success");
				}else if(true){//FIXME
					System.out.println("You were already registered in the server");
				}
				break;
			//SAVE PASSWORD
			case 3:
				if(!initiated){
					System.err.println("you need to call init in order to contact server");
					continue;
				}
				System.out.println("Insert:\n\"Domain Username Password\"");
				s.nextLine();
				input = s.nextLine();
				spl = input.split(" ");
				try {
					if(spl.length != 3){
						System.err.println("3 parameters expected");
						continue;
					}
					l.save_password(spl[0].getBytes("UTF-8"), spl[1].getBytes("UTF-8"), spl[2].getBytes("UTF-8"));
				} catch(SocketException e){
					System.out.println("Server not available. Exiting..");
					var = false;
				} catch (IOException e) {
					e.printStackTrace();
				}

				break;
			//RETRIEVE PASSWORD
			case 4:
				if(!initiated){
					System.err.println("you need to call init in order to contact server");
					continue;
				}
				System.out.println("Insert:\n\"Domain Username\"");
				s.nextLine();
				input = s.nextLine();
				spl = input.split(" ");
				if(spl.length != 2){
					System.err.println("2 parameters expected");
					continue;
				}
				String pass = l.retrieve_password(spl[0].getBytes(), spl[1].getBytes());
				if(pass == null){
					System.out.println("No password found!");
				}
				else {
					System.out.println("Password: " + pass);
				}
				break;
			//CLOSE
			case 5:
				var = false;
				l.close();
				System.out.println("closed with success");
				break;
			default:
				System.out.println("Invalid argument. Try again");
			}
		}
		s.close();
	}
}
