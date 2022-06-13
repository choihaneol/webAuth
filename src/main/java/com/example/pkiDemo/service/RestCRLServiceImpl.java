package com.example.pkiDemo.service;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.example.pkiDemo.entity.CA;
import com.example.pkiDemo.entity.CAType;
import com.example.pkiDemo.entity.CRL_;
import com.example.pkiDemo.entity.Certificate_;
import com.example.pkiDemo.entity.RevokedCertificate;
import com.example.pkiDemo.repository.CARepository;
import com.example.pkiDemo.repository.CRLRepository;
import com.example.pkiDemo.repository.CertRepository;
import com.example.pkiDemo.repository.RVKRepository;

@Service
public class RestCRLServiceImpl implements RestCRLService {

	@Autowired
	private CARepository caRepo;

	@Autowired
	private CertRepository certRepo;

	@Autowired
	private CRLRepository crlRepo;

	@Autowired
	private RVKRepository revokedRepo;

	@Autowired
	private CertService crtService;

	@Autowired
	private RestCertService restCertService;

	@Override
	public List<CRL_> getCrlList() { // CRL 목록
		return crlRepo.findAll();
	}

	@Override
	public List<RevokedCertificate> getRevokedList() { // CRL 목록
		return revokedRepo.findAll();
	}

	public void delete(Integer revokedCertificate) {
		revokedRepo.deleteById(revokedCertificate);
	}
	
	

	public X509CRL generateICACRL(int certId, int issuerId, String issuerName, CAType caType)
			throws NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, CRLException {
		addBouncyCastleAsSecurityProvider();

		Certificate_ crt = certRepo.findOneByCertId(certId); // 삭제할 인증서 ID

		CA ca = crt.getCa();
		// int caId = ca.getCaId(); // 삭제할 인증서 기관의 ID
		// int issuerid= ca.getIssuerId();

		Certificate_ cert = ca.getCertificate();

		CA issuerCA = caRepo.findOneByCaId(ca.getIssuerId()); // issuerCA : 삭제할 인증서 발급기관
		String issuer;

		if (issuerCA.getCaType() == CAType.ROOTCA) {
			issuer = issuerCA.getCertificate().getSubjectName();
		} else if (issuerCA.getCaType() == CAType.ICA) {
			issuer = issuerCA.getCertificate().getSubjectName();
		} else {
			issuer = issuerCA.getCertificate().getSubjectName();
		}

		Date now = new Date();

		// generate a key pair
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
		keyPairGenerator.initialize(2048, new SecureRandom());
		// KeyPair keyPair = keyPairGenerator.generateKeyPair();

		// test (CRL검증 실패 시나리오. 상위기관이 2로 고정되있음 )
		/*
		 * CA issuerTest = caRepo.findOneByCaId(2); ContentSigner signer = new
		 * JcaContentSignerBuilder("SHA256WithRSA") // 알고리즘, 개인키, 서명 .setProvider(new
		 * BouncyCastleProvider()).build(issuerTest.getCertificate().getPrivateKey());
		 */

		// signiture
		ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA") // 알고리즘, 개인키, 서명
				.setProvider(new BouncyCastleProvider()).build(issuerCA.getCertificate().getPrivateKey());

		// build a CRL generator
		X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(new X500Name(issuer), cert.getExpiredDateStart()); // 발급자,마지막업데이트날

		// JcaX509v2CRLBuilder
		crlBuilder.addCRLEntry(cert.getSerialNumber(), now, CRLReason.superseded); // 시리얼넘버, 취소날짜, 취소이유
		// crlBuilder.setNextUpdate(new Date(1603092045)); // 만료 날짜 오류 발생 test용
		crlBuilder.setNextUpdate(cert.getExpiredDateEnd()); // 만료 날짜

		crlBuilder.build(signer);
		X509CRLHolder crlHolder = crlBuilder.build(signer);

		X509CRL crl = new JcaX509CRLConverter().setProvider(new BouncyCastleProvider()).getCRL(crlHolder);

		// CRL DB저장
		CRL_ crl_ = new CRL_();

		crl_.setCa(issuerCA);
		crl_.setCrlIssuerDigitalSigniture(cert.getCaDigitalSigniture());
		crl_.setSignature(Hex.toHexString(cert.getCaDigitalSigniture()));
		crl_.setCrlIssuerName(issuer);
		crl_.setUpdateDateLast(cert.getExpiredDateStart());
		crl_.setUpdateDateNext(crl.getNextUpdate());
		crl_.setRawData(crl.getEncoded());

		CRL_ newCrl = crlRepo.save(crl_);

		// 폐지인증서 추가. 폐지인증서는 serial number가 있으니까 rawdata는 필요없음
		RevokedCertificate revokedCert = new RevokedCertificate();
		revokedCert.setCrl(newCrl);

		Date newnow = new Date();
		SimpleDateFormat format1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		String nowFormat = format1.format(newnow);

		revokedCert.setRevocationDate(nowFormat);
		revokedCert.setRevokedReason(CRLReason.superseded);
		revokedCert.setCertificateSerialNumber(cert.getSerialNumber());

		RevokedCertificate newRevokedCert = revokedRepo.save(revokedCert);

		// view
		crl_setRevokedCerts(newRevokedCert);

		crlRepo.save(newCrl);
		issuerCA.setCrlId(newCrl.getCrlId()); // 새로 발급한 CRL의 ID

		caRepo.save(issuerCA);
		System.out.println(crl);

		return (X509CRL) crl; // X509CRL로 변환 필요
	}
	
	
	

	private void crl_setRevokedCerts(RevokedCertificate newRevokedCert) {
		// TODO Auto-generated method stub

	}
	
	
	

	@Override
	public void addBouncyCastleAsSecurityProvider() {
		Security.addProvider(new BouncyCastleProvider());
	}

	
	
	
	public boolean revokeCertificate(int certId, int issuerId, String issuerName, CAType caType)
			throws NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, CRLException,
			CertificateException, ClassCastException, IOException {
		addBouncyCastleAsSecurityProvider();

		Certificate_ crt = certRepo.findOneByCertId(certId); // 삭제할 인증서 ID

		CA ca = crt.getCa();

		Certificate_ cert = ca.getCertificate();

		CA issuerCA = caRepo.findOneByCaId(ca.getIssuerId()); // 삭제할 인증서 발급기관의 ID

		Date now = new Date();
		SimpleDateFormat format1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		String nowFormat = format1.format(now);

		// CRL DB저장
		CRL_ crl_ = crlRepo.findOneByCrlId(issuerCA.getCrlId()); // originalCrlId

		// CRL에 폐기인증서 rawdata 저장
		String issuer;

		if (issuerCA.getCaType() == CAType.ROOTCA) {
			issuer = issuerCA.getCertificate().getSubjectName();
		} else if (issuerCA.getCaType() == CAType.ICA) {
			issuer = issuerCA.getCertificate().getSubjectName();
		} else {
			issuer = issuerCA.getCertificate().getSubjectName();
		}

		// rawdata parsing
		byte[] bytes = crl_.getRawData();
		String s = new String(bytes, StandardCharsets.US_ASCII);
		String st = new String(bytes, StandardCharsets.UTF_8);

		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		CRL crl = cf.generateCRL(new ByteArrayInputStream(crl_.getRawData()));
		X509CRL x509crl = (X509CRL) crl;

		// build a CRL generator
		X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(new X500Name(issuer), cert.getExpiredDateStart()); // 발급자,취소날짜

		for (X509CRLEntry entry : x509crl.getRevokedCertificates()) {
			crlBuilder.addCRLEntry(entry.getSerialNumber(), entry.getRevocationDate(),
					entry.getRevocationReason().ordinal());
		}

		// JcaX509v2CRLBuilder
		crlBuilder.addCRLEntry(cert.getSerialNumber(), now, CRLReason.superseded); // 시리얼넘버, 취소날짜, 취소이유

		// signiture
		ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA") // 알고리즘, 개인키, 서명
				.setProvider(new BouncyCastleProvider()).build(issuerCA.getCertificate().getPrivateKey()); // 인증서나 CRL 발급할때 상위기관키로 발급

		crlBuilder.setNextUpdate(cert.getExpiredDateEnd()); // 만료 날짜
		crlBuilder.build(signer);
		X509CRLHolder crlHolder = crlBuilder.build(signer);

		X509CRL newCrl = new JcaX509CRLConverter().setProvider(new BouncyCastleProvider()).getCRL(crlHolder);

		// CRL DB저장
		// crl_.setCa(issuerCA);
		crl_.setCrlIssuerDigitalSigniture(newCrl.getSignature());
		crl_.setSignature(Hex.toHexString(newCrl.getSignature()));
		// crl_.setCrlIssuerName(issuer);
		crl_.setUpdateDateLast(newCrl.getThisUpdate());
		crl_.setUpdateDateNext(newCrl.getThisUpdate());
		crl_.setRawData(newCrl.getEncoded());

		// 폐지인증서 업데이트 (기존의 CRL에 같은 일련번호 있으면 업데이트된 폐지인증서로 대체)

		for (int i = 0; i < crl_.getRevokedCerts().size(); i++) {

			int CertTobeRevoked = cert.getSerialNumber().intValue(); // 삭제할 인증서
			int CertAlreadyRevoked = crl_.getRevokedCerts().get(i).getCertificateSerialNumber().intValue(); // 기존의 폐지된인증서

			if (CertTobeRevoked == CertAlreadyRevoked) {

				// 기존의것 삭제
				revokedRepo.deleteById(crl_.getRevokedCerts().get(i).getRevokedCertificateId());

				break;

			}
		}

		// 폐지인증서 추가. 폐지인증서는 serial number가 있으니까 rawdata는 필요없음
		RevokedCertificate revokedCert = new RevokedCertificate();
		revokedCert.setCrl(crl_);
		revokedCert.setRevocationDate(nowFormat);
		revokedCert.setRevokedReason(CRLReason.superseded);
		revokedCert.setCertificateSerialNumber(cert.getSerialNumber());

		RevokedCertificate newRevokedCert = revokedRepo.save(revokedCert);

		// view
		crl_.getRevokedCerts().add(newRevokedCert); // List<RevokedCertificate> 로 해서에러 떴었음

		// CRL rawdata 추가 한거
		// crl_.setRawData(crl.getEncoded());

		crlRepo.save(crl_);// 기존의 폐지인증서를 지우고 새로운 일련번호의 인증서를 추가

		System.out.println(crl_);

		return true;

	}

	
	
	
	// cert : 대상인증서, cert : 경로내인증서
	public boolean validateCRLNewNew(boolean result, Certificate_ cert, List<Certificate_> certChain,
			Certificate_ certInChain) throws CertificateException, CRLException, InvalidKeyException,
			NoSuchAlgorithmException, NoSuchProviderException, SignatureException {

		CA issuer = caRepo.findOneByCaId(certInChain.getIssuerId()); // 대상 인증서 발급자
		CA currentCA = certInChain.getCa();
		CRL_ crl = crlRepo.findOneByCrlId(issuer.getCrlId());

		CRL_ crl2 = crlRepo.findOneByCrlId(currentCA.getCrlId());

		if (crl == null) {
			return true;
		}

		// CRL_ → X509CRL 타입 변환
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		CRL crltemp = cf.generateCRL(new ByteArrayInputStream(crl.getRawData()));
		X509CRL X509crl = (X509CRL) crltemp; // java.security.cert.X509CRL

		// (1)유효기간
		Date time = new Date();
		int compare = time.compareTo(X509crl.getNextUpdate());
		if (compare < 0) {
			result = true;
		} else {
			result = false;
			return result;
		}

		// (2)발급자 DN
		if (issuer.getCaType() != CAType.ROOTCA) {

			byte[] certRawdata = currentCA.getCertificate().getRawData(); // Certificate_→X509Certificate
			CertificateFactory certcf = CertificateFactory.getInstance("X.509");
			Certificate certificate = certcf.generateCertificate(new ByteArrayInputStream(certRawdata));

			CertificateFactory crlcf = CertificateFactory.getInstance("X.509"); // CRL_ →X509CRL
			CRL_ tempcrl = crlRepo.findOneByCrlId(issuer.getCrlId()); // DB에서 CRL발급자는 인증서기관이 아닌 상위기관으로 등록되어있음.

			CRL crl_ = crlcf.generateCRL(new ByteArrayInputStream((tempcrl.getRawData())));
			X509CRL x509crl = (X509CRL) crl_;

			String certIssuer = ((X509Certificate) certificate).getIssuerDN().getName();
			Principal crlIssuer = x509crl.getIssuerDN();

			if (certIssuer.equals(crlIssuer.toString())) {
				result = true;
			} else {
				result = false;
				return result;
			}
		}

		// (3)CRL발급자 경로검증(인증서경로 검증. CRL발급자부터 타고 올라감)
		// (3-1) 인증서경로 획득
		CA currentCertIssuer = caRepo.findOneByCaId(certInChain.getIssuerId());
		List<Certificate_> crlChain = new ArrayList<>();

		crlChain.add(currentCertIssuer.getCertificate());

		while (currentCertIssuer.getCaType() != CAType.ROOTCA) { // 무한루프 깨는곳
			CA CAtemp = caRepo.findOneByCaId(currentCertIssuer.getIssuerId());
			currentCertIssuer = CAtemp;
			crlChain.add(currentCertIssuer.getCertificate());

			if (currentCertIssuer.getCaType() == CAType.ROOTCA) {
				break;
			}
		}

		for (int i = 0; i < crlChain.size(); i++) {
			result = restCertService.validateCertNewNew(result, cert, crlChain, null);

		}

		// (4)CRL서명검증
		byte[] crlRawdata = null;
		CA upperCA = caRepo.findOneByCaId(cert.getIssuerId());
		crlRawdata = crl.getRawData();
		CertificateFactory crlcf2 = CertificateFactory.getInstance("X.509"); // CRL_ → X509CRL
		CRL crl2_ = crlcf2.generateCRL(new ByteArrayInputStream(crlRawdata));
		X509CRL x509crl2 = (X509CRL) crl2_;

		try {
			x509crl2.verify(issuer.getCertificate().getPublicKey());
			result = true;

		} catch (Exception e) {
			result = false;
			return result;
		}

		CertificateFactory cf1 = CertificateFactory.getInstance("X.509");// 대상인증서 certificate 타입으로 변경
		Certificate certToCompare = cf1.generateCertificate(new ByteArrayInputStream(cert.getRawData())); // 인증서 타입변환

		boolean revoked = x509crl2.isRevoked(certToCompare);

		if (revoked) {
			result = false;
		} else {
			result = true;
			return result;
		}

		return result;
	}
	
	
	

	public CRL downloadCRL(int crlId, CRL_ crl, byte[] rawdata)
			throws FileNotFoundException, CRLException, CertificateException { // 파일업로드

		String fileName = "crl" + crlId;
		FileOutputStream fos = new FileOutputStream(new File(fileName + ".crl"));

		CertificateFactory crlcf = CertificateFactory.getInstance("X.509"); // CRL_ → X509CRL
		CRL crlToDownload = crlcf.generateCRL(new ByteArrayInputStream(rawdata));

		try {
			fos.write((rawdata));
		} catch (IOException e) {
			e.printStackTrace();
		} // 파일로저장
		try {
			fos.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return crlToDownload;
	}

}
