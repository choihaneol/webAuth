package com.example.pkiDemo.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
import javax.persistence.Table;

import com.sun.istack.NotNull;

@Entity
@Table(name = "ca", schema = "data_tables", catalog = "")
public class CA {
	


	@Id // PK
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "ca_id")
	private int caId;


	@OneToOne //원래 1:1 이었는데, 검증에서 기관별 인증서 불러오기 때문에 n:1으로 바꿧다가 다시 수정함.
	@JoinColumn(name = "cert_id")
	private Certificate_ certificate;

	
	@Column(name = "crl_id")
	private int crlId;
	
	@Column(name = "ca_name")
	private String caName;

    @Column(name = "issuer_id")
	private int issuerId;

	@Column(name = "ca_type", nullable = false)
	@Enumerated(EnumType.STRING) // public enum CA_Type { ROOTCA, ICA, ENDENTITY }
	@NotNull
	private CAType caType;
	
	
	public CA() {
	}
	
	public CA(int certId, int crlId, String caName, int issuerId, CAType caType) {
		super();
		this.crlId = crlId;
		this.caName = caName;
		this.issuerId = issuerId;
		this.caType = caType;
	}

	public int getCaId() {
		return caId;
	}


	public void setCaId(int caId) {
		this.caId = caId;
	}

	public Certificate_ getCertificate() {
		return certificate;
	}


public void setCertificate(Certificate_ certificate) {
		this.certificate = certificate;
	}

	public int getCrlId() {
		return crlId;
	}

	public void setCrlId(int crlId) {
		this.crlId = crlId;
	}

	public String getCaName() {
		return caName;
	}

	public void setCaName(String caName) {
		this.caName = caName;
	}

	public int getIssuerId() {
		return issuerId;
	}

	public void setIssuerId(int issuerId) {
		this.issuerId = issuerId;
	}

	public CAType getCaType() {
		return caType;
	}

	public void setCaType(CAType caType) {
		this.caType = caType;
	}


 @Override
	public String toString() {
		return "CA ID : " + caId + ", Certificate ID : " + certificate + ", " + crlId + ", CA Name : " + caName
				+ ", Issuer Id : " + issuerId + "CA Type : " + caType;
	}
	
	
	
}


//※Reference : https://limkydev.tistory.com/66 - enum 활용  
//※Reference : https://kihoonkim.github.io/2017/01/27/JPA(Java%20ORM)/3.%20JPA-%EC%97%94%ED%8B%B0%ED%8B%B0%20%EB%A7%A4%ED%95%91/ - DB 연관관계 설정
//※Reference : https://jdm.kr/blog/142 - DB 연관관계 설정 !!!!!!!!!!! 브라우저 인풋 데이터 연동해서 확인하기