package pt.ist.sec.proj;

import java.io.IOException;
import java.security.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class Client {

	public static void main(String args[]){
		
		Library l = new Library();
		
		
		System.out.println("CLIENT START");
		System.out.println("1 - Init");
		System.out.println("2 - Register");
		System.out.println("3 - Save password");
		System.out.println("4 - Retrieve password");
		System.out.println("5 - Close");
		Scanner s = new Scanner(System.in);
		int option = 0;
		String input;
		String[] spl;
		while(true){
			option = s.nextInt();
			switch(option){
				case 1:
					System.out.println("Enter your KeyStore password");
					s.nextLine();
					input = s.nextLine();
					l.init(null, input);
					break;
				case 2:
					l.register(null);
					break;
				case 3:
					System.out.println("Enter domain username password");
					s.nextLine();
					input = s.nextLine();
					spl = input.split(" ");
					try {
						System.out.println(spl[0].getBytes());
						System.out.println(spl[1].getBytes());
						System.out.println(spl[2].getBytes());
						l.save_password(spl[0].getBytes(), spl[1].getBytes(), spl[2].getBytes());
					} catch (IOException e) {
						e.printStackTrace();
					}
					break;
				case 4:
					System.out.println("Enter domain username");
					s.nextLine();
					input = s.nextLine();
					spl = input.split(" ");
					l.retrieve_password(spl[0].getBytes(), spl[1].getBytes());
					break;
				case 5:
					l.close();
					System.exit(0);
			}
		}
	}
}
