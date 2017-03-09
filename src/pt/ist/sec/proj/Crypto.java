package pt.ist.sec.proj;

import java.io.UnsupportedEncodingException;
import java.util.Base64;

public class Crypto {

	public String base64encode(byte[] bytes){
		Base64.Encoder encoder = Base64.getEncoder();
		return encoder.encodeToString(bytes);
	}
	
	public byte[] base64decode(String s){
		Base64.Decoder decoder = Base64.getDecoder();
		return decoder.decode(s);
	}
	
	
	
	/*
	public static void main(String args[]){
		try {
			Crypto c = new Crypto();
			String stringToEncode = "o vasco é um merdas";
			System.out.println(stringToEncode);
			
			String encoded = c.base64encode(stringToEncode.getBytes("UTF-8"));
			System.out.println(encoded);
					
			String original = new String(c.base64decode(encoded), "UTF-8");
			System.out.println(original);
		} catch (UnsupportedEncodingException e1) {
			e1.printStackTrace();
		}
	}*/
		

		
	
}
