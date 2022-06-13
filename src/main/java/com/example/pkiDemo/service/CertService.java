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

import com.example.pkiDemo.entity.CA;
import com.example.pkiDemo.entity.CAType;
import com.example.pkiDemo.entity.Certificate_;

public interface CertService {

	void saveCA(CA ca); // 기관 저장

	List<CA> getList(); // 기관 목록

	Certificate_ getCert(int certId); // 인증서조회

	void saveCert(Certificate_ certificate); // 인증서저장

	Certificate generateSelfSignedX509RootCertificate() // RootCA 발급
			throws InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException,
			SignatureException, OperatorCreationException, CertificateException;

	void generateCert(String UserName, String company, String email, CAType catype, CA caid) // 인증서발급
			throws InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException,
			SignatureException, OperatorCreationException, CertificateException, InvalidKeySpecException;

	/*
	 * void delete(int certId, int issuerId, String issuerName, CAType caType) //
	 * 인증서삭제 throws InvalidKeyException, IllegalStateException,
	 * NoSuchProviderException, NoSuchAlgorithmException, SignatureException,
	 * OperatorCreationException, CertificateException, InvalidKeySpecException,
	 * CRLException, IOException;
	 */
	public Certificate generateSelfSignedX509CACertificate(String userName, String company, String email,
			CAType issuerCaType, CA issuer) // ICA 발급
			throws InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException,
			SignatureException, OperatorCreationException, CertificateException, InvalidKeySpecException;

	void addBouncyCastleAsSecurityProvider();

	int validateCertNew(Certificate_ cert, int result, CA certIssuer) throws CertificateException, InvalidKeyException,
			NoSuchAlgorithmException, NoSuchProviderException, SignatureException, CRLException;

	int validateCertNewNew(int result, Certificate_ cert, List<Certificate_> certChain, CA certIssuer)
			throws CertificateException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
			SignatureException, CRLException;

	void downloadCert(int certId, Certificate_ cert, byte[] rawdata) throws FileNotFoundException;

}
