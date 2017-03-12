package pt.ist.sec.proj;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
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
	
	public KeyStore getKeyStore(String pass){ //created with "ola" as password
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
		while(true){
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
				case 1:
					System.out.println("Enter your KeyStore password:");
					s.nextLine();
					input = s.nextLine();
					KeyStore ks = c.getKeyStore(input);
					if(ks==null){
						System.err.println("wrong password, try again");
						continue;
					} //FIXME returns success?
					l.init(ks, input);
					initiated =true;
					break;
				case 2:
					l.register(null);
					break;
				case 3:
					if(!initiated){
						System.err.println("you need to call init in order to contact server");
						continue;
					}
					System.out.println("Enter Domain Username Password");
					s.nextLine();
					input = s.nextLine();
					spl = input.split(" ");
					try {
						if(spl.length != 3){
							System.err.println("3 parameters expected");
							continue;
						}
						l.save_password(spl[0].getBytes("UTF-8"), spl[1].getBytes("UTF-8"), spl[2].getBytes("UTF-8"));
					} catch (IOException e) {
						e.printStackTrace();
					}
					
					break;
				case 4:
					if(!initiated){
						System.err.println("you need to call init in order to contact server");
						continue;
					}
					System.out.println("Enter Domain Username");
					s.nextLine();
					input = s.nextLine();
					spl = input.split(" ");
					if(spl.length != 2){
						System.err.println("2 parameters expected");
						continue;
					}
					byte[] pass = l.retrieve_password(spl[0].getBytes(), spl[1].getBytes());
					if(pass == null){
						System.out.println("No password found!");
					}
					else {
						try {
							System.out.println("Password: " + new String(pass, "UTF-8"));
						} catch (UnsupportedEncodingException e) {
							e.printStackTrace();
						}
					}
					break;
				case 5:
					l.close();
					initiated=false;
					System.out.println("closed with success");
					break;
				default:
					System.out.println("Invalid argument. Try again");
			}
		}
	}
}
