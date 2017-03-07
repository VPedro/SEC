package pt.ist.sec.proj;

import java.io.IOException;
import java.security.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class Client {

	public static void main(String args[]){
		System.out.println("CLIENT START");
		
		Library l = new Library();
		
		try {
			l.save_password("MyDomain", "MyUsername", "MyPassword");
		} catch(IOException e) {
			System.out.println("Exception: IOException!");
		}
	}
	
}
