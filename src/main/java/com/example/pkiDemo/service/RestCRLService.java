package com.example.pkiDemo.service;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.util.List;

import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.stereotype.Service;

import com.example.pkiDemo.entity.CAType;
import com.example.pkiDemo.entity.CRL_;
import com.example.pkiDemo.entity.Certificate_;
import com.example.pkiDemo.entity.RevokedCertificate;

@Service
public interface RestCRLService {

List<CRL_> getCrlList(); // CRL 목록	
	
	List<RevokedCertificate> getRevokedList(); // CRL별 폐지인증서 목록
	
	void delete(Integer revokedCertificate);
	
	X509CRL generateICACRL(int certId, int issuerId, String issuerName, CAType caType)
			throws NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException,
			CRLException;
	
	boolean revokeCertificate(int certId, int issuerId, String issuerName, CAType caType)
			throws NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException,
			CRLException, CertificateException, ClassCastException, IOException;
		
	void addBouncyCastleAsSecurityProvider();
	
	boolean validateCRLNewNew(boolean result, Certificate_ cert, List<Certificate_> certChain,
		Certificate_ currentCertInChain) throws CertificateException, CRLException,
	    InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException;
	
	CRL downloadCRL(int crlId, CRL_ crl, byte[] rawdata) throws FileNotFoundException,
	     CRLException, CertificateException; // 파일업로드


}
