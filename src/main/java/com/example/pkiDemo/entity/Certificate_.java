package com.example.pkiDemo.entity;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.Lob;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.persistence.Transient;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.util.encoders.Hex;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonProperty.Access;

@Entity
@Table(name = "certificate", schema = "data_tables", catalog = "")
public class Certificate_ {

	@Id // PK
	@Column(name = "cert_id")
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private int certId;

	//@JsonIgnore
	@JsonProperty(access = Access.WRITE_ONLY)
	@ManyToOne(targetEntity = CA.class, fetch = FetchType.LAZY) // FK
	@JoinColumn(name = "ca_id") // certificate테이블의 ca_id컬럼이 ca테이블의 id로 정의됨.
	private CA ca;

	@Column(name = "serial_number") // int -> BigInteger 변경
	private BigInteger serialNumber;

	@Column(name = "issuer_name") // issuerName -> issuerId로 변경
	private String issuerName;

	@GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "ORDER_SEQ_GENERATOR")
	@Column(name = "issuer_id") // issuerId 추가
	private int issuerId;

	@Column(name = "expired_date_start") // Timestamp -> Date 변경
	private Date expiredDateStart;

	@Column(name = "expired_date_end")
	private Date expiredDateEnd;

	@Column(name = "subject_name")
	private String subjectName;

	@JsonIgnore
	@Lob // BLOB 타입 매핑시 //byte[] -> PublicKey 변경
	@Column(name = "public_key")
	private PublicKey publicKey;

	@JsonIgnore
	@Lob
	@Column(name = "private_key")
	private PrivateKey privateKey; // byte[] -> PrivateKey 변경

	@Lob
	@Column(name = "ca_digital_signiture")
	private byte[] caDigitalSigniture;

	@Transient
	private String signature;

	public String getSignature() {
		return signature;
	}

	public void setSignature(String signature) {
		this.signature = signature;
	}

	@Lob
	@Column(name = "raw_data") // byte[] -> Certificate 변경
	private byte[] rawData;

	// Field value
	@Column(name = "user_name")
	private String userName;

	@Column(name = "company")
	private String company;

	@Column(name = "email")
	private String email;

	public Certificate_() {
	}

	public Certificate_(CA ca, BigInteger serialNumber, String issuerName, int issuerId, Date expiredDateStart,
			Date expiredDateEnd, String subjectName, PublicKey publicKey, PrivateKey privateKey,
			byte[] caDigitalSigniture, byte[] rawData) {
		super();
		this.ca = ca;
		this.serialNumber = serialNumber;
		this.issuerName = issuerName;
		this.issuerId = issuerId;
		this.expiredDateStart = expiredDateStart;
		this.expiredDateEnd = expiredDateEnd;
		this.subjectName = subjectName;
		this.publicKey = publicKey;
		this.privateKey = privateKey;
		this.caDigitalSigniture = caDigitalSigniture;
		this.rawData = rawData;
		this.signature = Hex.toHexString(caDigitalSigniture);

	}

	public int getCertId() {
		return certId;

	}

	public void setCertId(int certId) {
		this.certId = certId;
	}

	public CA getCa() {
		return ca;
	}

	public void setCa(CA ca) {
		this.ca = ca;
	}

	public BigInteger getSerialNumber() {
		return serialNumber;
	}

	public void setSerialNumber(BigInteger serialNumber) {
		this.serialNumber = serialNumber;
	}

	public String getIssuerName() {
		return issuerName;
	}

	public void setIssuerName(String issuerName) {
		this.issuerName = issuerName;
	}

	public int getIssuerId() {
		return issuerId;
	}

	public void setIssuerId(int issuerId) {
		this.issuerId = issuerId;
	}

	public Date getExpiredDateStart() {
		return expiredDateStart;
	}

	public void setExpiredDateStart(Date expiredDateStart) {
		this.expiredDateStart = expiredDateStart;
	}

	public Date getExpiredDateEnd() {
		return expiredDateEnd;
	}

	public void setExpiredDateEnd(Date expiredDateEnd) {
		this.expiredDateEnd = expiredDateEnd;
	}

	public String getSubjectName() {
		return subjectName;
	}

	public void setSubjectName(String subjectName) {
		this.subjectName = subjectName;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public byte[] getCaDigitalSigniture() {
		return caDigitalSigniture;
	}

	public void setCaDigitalSigniture(byte[] caDigitalSigniture) {
		this.caDigitalSigniture = caDigitalSigniture;
	}

	public byte[] getRawData() {
		return rawData;
	}

	public void setRawData(byte[] rawData) {
		this.rawData = rawData;
	}

	// Field value
	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String getCompany() {
		return company;
	}

	public void setCompany(String company) {
		this.company = company;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	@Override
	public String toString() {
		String result = "certificate ID : " + certId;
		return result;
	}

	public String toStringField() {
		return "userName : " + userName + ", company : " + company + ", email " + email;
	}

}