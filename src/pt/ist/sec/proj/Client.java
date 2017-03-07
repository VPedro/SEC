package pt.ist.sec.proj;

import java.security.*;

public class Client {

	public static void main(String args[]){
		System.out.println("CLIENT START");
		Library l = new Library();
		l.init(null);
		
		byte[] byteArray; 
		String savePW = "MyPassword";
		byteArray = savePW.getBytes();
		l.test(byteArray);
	}
	
}
