package com.example.pkiDemo.entity;

import java.sql.Timestamp;
import java.util.Date;
import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.Lob;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.bouncycastle.util.encoders.Hex;

import com.fasterxml.jackson.annotation.JsonIgnore;

@Entity
@Table(name = "crl", schema = "data_tables", catalog = "")
public class CRL_ {

	@Id // PK
	@Column(name = "crl_id")
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private int crlId;

	// @JsonIgnore
	@ManyToOne(targetEntity = CA.class, fetch = FetchType.LAZY) // FK
	@JoinColumn(name = "ca_id")
	private CA ca;

	@JsonIgnore
	@OneToMany
	@JoinColumn(name = "crl_id")
	private List<RevokedCertificate> revokedCerts;

	@Column(name = "crl_issuer_name")
	private String crlIssuerName;

	public List<RevokedCertificate> getRevokedCerts() {
		return revokedCerts;
	}

	public void setRevokedCerts(List<RevokedCertificate> revokedCerts) {
		this.revokedCerts = revokedCerts;
	}

	@Column(name = "update_date_next")
	private Date updateDateNext;

	@Column(name = "update_date_last")
	private Date updateDateLast;

	@Lob // BLOB 타입 매핑시
	@Column(name = "crl_issuer_digital_signiture")
	private byte[] crlIssuerDigitalSigniture;

	@Transient
	private String signature;

	@Lob
	@Column(name = "raw_data") // byte[], X509CRL , crl 다 에러
	private byte[] rawData;

	public CRL_() {
	}

	public CRL_(CA ca, String crlIssuerName, Timestamp updateDateNext, Timestamp updateDateLast,
			byte[] crlIssuerDigitalSigniture, byte[] rawData) {
		super();
		this.ca = ca;
		this.crlIssuerName = crlIssuerName;
		this.updateDateNext = updateDateNext;
		this.updateDateLast = updateDateLast;
		this.crlIssuerDigitalSigniture = crlIssuerDigitalSigniture;
		this.rawData = rawData;
		this.signature = Hex.toHexString(crlIssuerDigitalSigniture);
	}

	public int getCrlId() {
		return crlId;
	}

	public void setCrlId(int crlId) {
		this.crlId = crlId;
	}

	public CA getCa() {
		return ca;
	}

	public void setCa(CA ca) {
		this.ca = ca;
	}

	public String getCrlIssuerName() {
		return crlIssuerName;
	}

	public void setCrlIssuerName(String crlIssuerName) {
		this.crlIssuerName = crlIssuerName;
	}

	public Date getUpdateDateNext() {
		return updateDateNext;
	}

	public void setUpdateDateNext(Date date) {
		this.updateDateNext = date;
	}

	public Date getUpdateDateLast() {
		return updateDateLast;
	}

	public void setUpdateDateLast(Date date) {
		this.updateDateLast = date;
	}

	public byte[] getCrlIssuerDigitalSigniture() {
		return crlIssuerDigitalSigniture;
	}

	public void setCrlIssuerDigitalSigniture(byte[] crlIssuerDigitalSigniture) {
		this.crlIssuerDigitalSigniture = crlIssuerDigitalSigniture;
	}

	public String getSignature() {
		return signature;
	}

	public void setSignature(String signature) {
		this.signature = signature;
	}

	public byte[] getRawData() {
		return rawData;
	}

	public void setRawData(byte[] rawData) {
		this.rawData = rawData;
	}

}