package pt.ist.sec.proj;

import java.io.Serializable;
import java.security.PublicKey;

public class AckMessage implements Serializable{

	private static final long serialVersionUID = 1L;
	private int id;
	private String func;
	private int ts;
	//not used yet
	private Long nonce;
	private byte[] signNonce;
	
	public AckMessage(String func, int ts) {
		this.func = func;
		this.ts = ts;
	}

		
	public String getFunc() {
		return func;
	}
	public void setFunc(String func) {
		this.func = func;
	}
	
	public int getTS() {
		return this.ts;
	}
	public void setTS(int ts) {
		this.ts = ts;
	}
	
		
	public void setID(int id){
		this.id = id;
	}
	public int getID(){
		return this.id;
	}
}
