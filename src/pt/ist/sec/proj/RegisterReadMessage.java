package pt.ist.sec.proj;

import java.io.Serializable;
import java.security.PublicKey;

public class RegisterReadMessage implements Serializable{

	private static final long serialVersionUID = 1L;
	private String func;
	private PublicKey pubKey;
	private byte[] signPK;
	private int rid;
	private byte[] signRID;
	private byte[] signDomain;
	private byte[] signUsername;
	private byte[] signPassword;
	private byte[] domain;
	private byte[] username;
	private byte[] password;
	private PublicKey clientPubKey;
	//not used yet
	private Long nonce;
	private byte[] signNonce;
	
	public RegisterReadMessage(PublicKey pubKey, byte[] signPK, int rid, byte[] signRID, PublicKey clientPubKey, byte[] domain, byte[] sig_domain, byte[] username, byte[] sig_username) {
		this.pubKey = pubKey;
		this.signPK = signPK;
		this.rid = rid;
		this.signRID = signRID;
		this.clientPubKey = clientPubKey;
		this.domain = domain;
		this.username = username;
		this.signDomain = sig_domain;
		this.signUsername = sig_username;
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
	

	
	public int getRID() {
		return rid;
	}
	public void setRID(int rid) {
		this.rid = rid;
	}
	
	public byte[] getsignRID() {
		return signRID;
	}
	public void setsignRID(byte[] sign) {
		this.signRID = sign;
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
		return clientPubKey;
	}


	public void setClientPubKey(PublicKey clientPubKey) {
		this.clientPubKey = clientPubKey;
	}


	
		
}
