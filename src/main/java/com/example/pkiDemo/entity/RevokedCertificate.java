package com.example.pkiDemo.entity;

import java.math.BigInteger;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

import com.fasterxml.jackson.annotation.JsonIgnore;

@Entity
@Table(name = "revoked_certificate", schema = "data_tables", catalog = "")
public class RevokedCertificate {

	@Id // PK
	@Column(name = "rv_cert_id")
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private int revokedCertificateId;

	// @JsonIgnore //지우면 JSON,서버 무한루프 돔
	// @NotFound(action = NotFoundAction.IGNORE)
	@ManyToOne(targetEntity = CRL_.class, fetch = FetchType.LAZY) // FK
	@JoinColumn(name = "crl_id") // revokedCertificateId테이블의 crl_id컬럼이 crl테이블의 id로 정의됨. nullable=false추가해봄
	private CRL_ crl;

	@Column(name = "certificate_serial_number")
	private BigInteger CertificateSerialNumber;

	@Column(name = "revocation_date")
	private String revocationDate;

	@Column(name = "revoked_reason")
	private int revokedReason;

	public RevokedCertificate() {
	}

	public RevokedCertificate(CRL_ crl, BigInteger CertificateSerialNumber, String revocationDate, int revokedReason) {
		super();
		this.crl = crl;
		this.CertificateSerialNumber = CertificateSerialNumber;
		this.revocationDate = revocationDate;
		this.revokedReason = revokedReason;
	}

	public int getRevokedCertificateId() {
		return revokedCertificateId;
	}

	public void setRevokedCertificateId(int revokedCertificateId) {
		this.revokedCertificateId = revokedCertificateId;
	}

	public CRL_ getCrl() {
		return crl;
	}

	public void setCrl(CRL_ crl) {
		this.crl = crl;
	}

	/*
	 * public int getCrlId() { return crlId; } ​ public void setCrlId(int crlId) {
	 * this.crlId = crlId; }
	 */

	public BigInteger getCertificateSerialNumber() {
		return CertificateSerialNumber;
	}

	public void setCertificateSerialNumber(BigInteger CertificateSerialNumber) {
		this.CertificateSerialNumber = CertificateSerialNumber;
	}

	public String getRevocationDate() {
		return revocationDate;
	}

	public void setRevocationDate(String now) {
		this.revocationDate = now;
	}

	public void setRevocationDate(Date now) {
		// TODO Auto-generated method stub

	}

	public int getRevokedReason() {
		return revokedReason;
	}

	public void setRevokedReason(int revokedReason) {
		this.revokedReason = revokedReason;
	}

}