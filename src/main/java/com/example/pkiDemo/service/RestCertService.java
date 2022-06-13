package com.example.pkiDemo.service;

import java.io.FileNotFoundException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.stereotype.Service;

import com.example.pkiDemo.entity.CA;
import com.example.pkiDemo.entity.CAType;
import com.example.pkiDemo.entity.Certificate_;

@Service
public interface RestCertService {

	void saveCA(CA ca); // 기관 저장

	List<CA> getList(); // 기관 목록

	Certificate_ getCert(int certId); // 인증서조회

	void saveCert(Certificate_ certificate); // 인증서저장

	Certificate generateSelfSignedX509RootCertificate() // RootCA 발급
			throws InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException,
			SignatureException, OperatorCreationException, CertificateException;

	Certificate generateCert(String UserName, String company, String email, CAType catype, CA caid) // 인증서발급
			throws InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException,
			SignatureException, OperatorCreationException, CertificateException, InvalidKeySpecException;

	public Certificate generateSelfSignedX509CACertificate(String userName, String company, String email, // ICA 발급
			CAType issuerCaType, CA issuer)
			throws InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException,
			SignatureException, OperatorCreationException, CertificateException, InvalidKeySpecException;

	void addBouncyCastleAsSecurityProvider();

	boolean validateCertNewNew(boolean result, Certificate_ cert, List<Certificate_> certChain, CA certIssuer)
			throws CertificateException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
			SignatureException, CRLException;

	Certificate downloadCert(int certId, Certificate_ cert, byte[] rawdata)
			throws FileNotFoundException, CertificateException;// 파일다운로드
}
