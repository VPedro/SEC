package pt.ist.sec.proj;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
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
	
	public static void main(String args[]){
		Client c = new Client();
		Library l = new Library();
		Scanner s = new Scanner(System.in);
		int option = 0;
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
					l.init(null, input);
					break;
				case 2:
					l.register(null);
					break;
				case 3:
					System.out.println("Enter Domain Username Password");
					s.nextLine();
					input = s.nextLine();
					spl = input.split(" ");
					try {
						l.save_password(spl[0].getBytes("UTF-8"), spl[1].getBytes("UTF-8"), spl[2].getBytes("UTF-8"));
					} catch (IOException e) {
						e.printStackTrace();
					}
					
					break;
				case 4:
					System.out.println("Enter Domain Username");
					s.nextLine();
					input = s.nextLine();
					spl = input.split(" ");
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
					System.exit(0);
				default:
					System.out.println("Invalid argument. Try again");
			}
		}
	}
}
