package pt.ist.sec.proj;

import java.io.Serializable;
import java.security.PublicKey;

public class RegisterMessage implements Serializable{

	private static final long serialVersionUID = 1L;
	private String func;
	private PublicKey pubKey;
	private byte[] signPK;
	private int wts;
	private byte[] signWTS;
	private byte[] signDomain;
	private byte[] signUsername;
	private byte[] signPassword;
	private byte[] domain;
	private byte[] username;
	private byte[] password;
	private PublicKey ClientPubKey;
	//not used yet
	private Long nonce;
	private byte[] signNonce;
	
	public RegisterMessage(String func, PublicKey pubKey, byte[] signPK, int wts, byte[] signWTS, 
						byte[] domain, byte[] signDomain, byte[] username, byte[] signUsername, 
						byte[] password, byte[] signPassword, Long nonce, byte[] signNonce, PublicKey clientPK) {
		this.func = func;
		this.pubKey = pubKey;
		this.signPK = signPK;
		this.wts = wts;
		this.signWTS = signWTS;
		this.domain = domain;
		this.signDomain = signDomain;
		this.username = username;
		this.signUsername = signUsername;
		this.password = password;
		this.signPassword = signPassword;
		this.setClientPubKey(clientPK);
		this.nonce = nonce;
		this.signNonce = signNonce;
	}

		
	public String getFunc() {
		return func;
	}
	public void setFunc(String func) {
		this.func = func;
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
	
	
	
	public int getWTS() {
		return wts;
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
	
	
	
	public Long getNonce() {
		return nonce;
	}
	public void setNonce(Long nonce) {
		this.nonce = nonce;
	}
	
	public byte[] getSignNonce() {
		return signNonce;
	}
	public void setSignNonce(byte[] signNonce) {
		this.signNonce = signNonce;
	}


	public PublicKey getClientPubKey() {
		return ClientPubKey;
	}

	public void setClientPubKey(PublicKey clientPubKey) {
		this.ClientPubKey = clientPubKey;
	}


	
		
}
