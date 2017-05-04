package pt.ist.sec.proj;

import java.io.Serializable;
import java.security.PublicKey;

public class ReadResponseMessage implements Serializable{

	private static final long serialVersionUID = 1L;
	private int id;
	private String func;
	private PublicKey pubKey;
	private byte[] signPK;
	private int rid;
	private byte[] signRID;
	private Integer wts;
	private byte[] signWTS;
	private byte[] signDomain;
	private byte[] signUsername;
	private byte[] signPassword;
	private byte[] domain;
	private byte[] username;
	private byte[] password;
	private PublicKey clientPubKey;

	//not used yet
	
	public ReadResponseMessage(PublicKey pubKey, byte[] signPK, int rid, byte[] signRID, int wts, byte[] signWTS, 
						byte[] domain, byte[] username, byte[] password, byte[] signPassword, PublicKey pk) {
		this.pubKey = pubKey;
		this.signPK = signPK;
		this.rid = rid;
		this.signRID = signRID;
		this.wts = wts;
		this.signWTS = signWTS;
		this.domain = domain;
		this.username = username;
		this.password = password;
		this.signPassword = signPassword;
		this.clientPubKey = pk;
	}


	public void setID(int id){
		this.id = id;
	}
	public int getID(){
		return this.id;
	}

		
	public String getFunc() {
		return func;
	}
	public void setFunc(String func) {
		this.func = func;
	}
	
	
	public PublicKey getClientPubKey() {
		return clientPubKey;
	}
	public void setClientPubKey(PublicKey key) {
		this.clientPubKey = key;
	}
	
	public PublicKey getPubKey() {
		return pubKey;
	}
	public void setPubKey(PublicKey key) {
		this.pubKey = key;
	}
	
	public byte[] getSignPK() {
		return signPK;
	}
	public void setSignPK(byte[] sign) {
		this.signPK = sign;
	}
	
	
	
	public int getRID() {
		return rid;
	}

	public void setRID(int rid) {
		this.rid = rid;
	}
	
	public byte[] getSignRID() {
		return signRID;
	}
	public void setSignRID(byte[] sign) {
		this.signRID = sign;
	}
	
	
	public Integer getWTS() {
		if(wts != null)
			return wts;
		return null;
	}

	public void setWTS(int wts) {
		this.wts = wts;
	}
	
	public byte[] getSignWTS() {
		return signWTS;
	}
	public void setSignWTS(byte[] sign) {
		this.signWTS = sign;
	}
	
	
	
	
	public byte[] getDomain() {
		return this.domain;
	}

	public void setDomain(byte[] value) {
		this.domain = value;
	}
	public byte[] getSignDomain() {
		return signDomain;
	}
	public void setSignDomain(byte[] sign) {
		this.signDomain = sign;
	}
	
	
	public byte[] getUsername() {
		return this.username;
	}

	public void setUsername(byte[] value) {
		this.username = value;
	}
	public byte[] getSignUsername() {
		return signUsername;
	}
	public void setSignUsername(byte[] sign) {
		this.signUsername = sign;
	}
	
	
	
	public byte[] getPassword() {
		return this.password;
	}

	public void setPassword(byte[] value) {
		this.password = value;
	}
	public byte[] getSignPassword() {
		return signPassword;
	}
	public void setSignPassword(byte[] sign) {
		this.signPassword = sign;
	}
	
	

	
		
}
