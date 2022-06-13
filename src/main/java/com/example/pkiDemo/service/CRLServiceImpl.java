package com.example.pkiDemo.service;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
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
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import javax.servlet.http.HttpServletResponse;

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
import org.springframework.data.repository.CrudRepository;
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
public class CRLServiceImpl implements CRLService {

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

		Certificate_ cert = ca.getCertificate();

		CA issuerCA = caRepo.findOneByCaId(ca.getIssuerId()); // issuerCA : 삭제할 인증서 발급기관
		String issuer;

		if (issuerCA.getCaType() == CAType.ROOTCA) { // 나중에 issuer 동적으로 수정
			issuer = issuerCA.getCertificate().getSubjectName();
		} else if (issuerCA.getCaType() == CAType.ICA) {
			issuer = issuerCA.getCertificate().getSubjectName();
		} else {
			issuer = issuerCA.getCertificate().getSubjectName();
		}

		Date now = new Date();

		// ======================================

		// generate a key pair
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
		keyPairGenerator.initialize(2048, new SecureRandom());

		// test (CRL검증 실패 시나리오. 상위기관이 2로 고정되있음)
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

		// (2)CRL의 발급자(인증기관) 설정
		// (3)발급시간 설정
		// (4)다음 업데이트시간 설정
		// (5)서명 알고리즘 설정
		// 폐지할 인증서의 일련번호를 엔트리에 추가
		// 서명이유
		// 서명하여 CRL 생성, 출력

		// CRL DB저장
		CRL_ crl_ = new CRL_(); // raw data는 인증서 converter 사용

		crl_.setCa(issuerCA);
		crl_.setCrlIssuerDigitalSigniture(cert.getCaDigitalSigniture());
		crl_.setSignature(Hex.toHexString(cert.getCaDigitalSigniture()));

		crl_.setCrlIssuerName(issuer);
		crl_.setUpdateDateLast(cert.getExpiredDateStart());

		crl_.setUpdateDateNext(crl.getNextUpdate());

		crl_.setRawData(crl.getEncoded()); // crl raw data 복호화 필요
		// crl_.setcrl(crl.getEncoded());// rawdata를 binary타입으로 저장되어 X509CRL 형식으로 변환 필요

		System.out.println("crl raw data : " + crl_.getRawData());

		CRL_ newCrl = crlRepo.save(crl_);

		// 폐지인증서 추가. 폐지인증서는 serial number 없음
		RevokedCertificate revokedCert = new RevokedCertificate();
		revokedCert.setCrl(newCrl);

		Date newnow = new Date();
		SimpleDateFormat format1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		String nowFormat = format1.format(newnow);

		revokedCert.setRevocationDate(nowFormat);
		revokedCert.setRevokedReason(CRLReason.superseded);
		revokedCert.setCertificateSerialNumber(cert.getSerialNumber());
		System.out.println("bouncyCastle 시리얼넘버저장완료 " + cert.getSerialNumber());
		System.out.println("bouncyCastle 시리얼넘버저장완료 " + revokedCert.getCertificateSerialNumber());

		RevokedCertificate newRevokedCert = revokedRepo.save(revokedCert);

		// view
		crl_setRevokedCerts(newRevokedCert);

		crlRepo.save(newCrl);
		issuerCA.setCrlId(newCrl.getCrlId()); // 새로 발급한 CRL의 ID

		caRepo.save(issuerCA);

		return (X509CRL) crl; // X509CRL로 변환 해야함
	}

	private void crl_setRevokedCerts(RevokedCertificate newRevokedCert) {
		// TODO Auto-generated method stub

	}

	@Override
	public void addBouncyCastleAsSecurityProvider() {
		Security.addProvider(new BouncyCastleProvider());
	}

	public X509CRL revokeCertificate(int certId, int issuerId, String issuerName, CAType caType,
			HttpServletResponse response) throws NoSuchAlgorithmException, NoSuchProviderException,
			OperatorCreationException, CRLException, CertificateException, ClassCastException, IOException {
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

		// CRL 에 추가로 폐기인증서 rawdata 저장
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
				.setProvider(new BouncyCastleProvider()).build(issuerCA.getCertificate().getPrivateKey());
		// CRL은 기존의 CRL에 폐지 인증서를 계속 추가해야하므로 상위기관의 키를 사용

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
		// Originalcrl.setRawData(crl);

		// 폐지인증서 업데이트 (기존의 CRL에 같은 일련번호 있으면 업데이트된 폐지인증서로 대체)
		for (int i = 0; i < crl_.getRevokedCerts().size(); i++) {
			System.out.println("getRevokedCerts()" + crl_.getRevokedCerts().get(i).getCertificateSerialNumber());

			int CertTobeRevoked = cert.getSerialNumber().intValue(); // 삭제할 인증서
			int CertAlreadyRevoked = crl_.getRevokedCerts().get(i).getCertificateSerialNumber().intValue(); // 기존의
																											// 폐지된인증서

			if (CertTobeRevoked == CertAlreadyRevoked) {

				// 기존의것 삭제
				revokedRepo.deleteById(crl_.getRevokedCerts().get(i).getRevokedCertificateId());

				response.setContentType("text/html; charset=UTF-8");
				PrintWriter out = response.getWriter();
				out.println("<script>alert('인증서가 폐지 되었습니다.'); history.go(-2);</script>"); // 2페이지 뒤로가기
				out.flush();

				break;

			}
		}

		// 폐지인증서 추가. 폐지인증서는 serial number가 있으니까 rawdata는 필요없고 DB에 저장
		RevokedCertificate revokedCert = new RevokedCertificate();
		revokedCert.setCrl(crl_);
		revokedCert.setRevocationDate(nowFormat);
		revokedCert.setRevokedReason(CRLReason.superseded);
		revokedCert.setCertificateSerialNumber(cert.getSerialNumber());
		System.out.println("bouncyCastle 시리얼넘버저장완료 " + cert.getSerialNumber());
		System.out.println("bouncyCastle 시리얼넘버저장완료 " + revokedCert.getCertificateSerialNumber());

		RevokedCertificate newRevokedCert = revokedRepo.save(revokedCert);

		// view
		crl_.getRevokedCerts().add(newRevokedCert); // List<RevokedCertificate 에러

		// CRL rawdata
		// crl_.setRawData(crl.getEncoded());

		crlRepo.save(crl_);

		System.out.println(crl_);

		return null;

	}

	// currentCert : chaincert, cert : currentcert
	public int validateCRL(int result, Certificate_ currentCert, Certificate_ cert, List<Certificate_> certChain)
			throws CertificateException, CRLException { // currentCA:검증하고자하는 인증서의 기관
		// CRL존재하지 않을때 (CRL ID = 0 이거나 CRL = Null) 예외처리

		int issuerId = currentCert.getIssuerId(); // 검증하고자 하는 인증서의 상위기관 ID
		CA issuerCA = caRepo.findOneByCaId(issuerId); // 검증하고자 하는 인증서의 상위기관. 인증서를 폐기하면 CRL은 상위기관CA의 CRL을 뒤져봐야함
		CRL_ currentCRL = crlRepo.findOneByCrlId(currentCert.getCa().getCrlId());
		CRL_ currentCertIssuerCRL = crlRepo.findOneByCrlId(issuerCA.getCrlId());

		System.out.println("검증하고자 하는 인증서 ID : " + currentCert.getCertId());
		System.out.println("검증하고자 하는 CA : " + currentCert.getCa().getCaId());
		System.out.println("검증하고자 하는 CRL ID (대상인증서의 기관의 CRL) : " + currentCert.getCa().getCrlId());

		if (currentCertIssuerCRL == null || currentCert.getCa().getCrlId() == 0) { // CRL 존재 X
			System.out.println("해당 인증기관은 폐지된 인증서가 존재하지 않아 CRL이 존재하지 않습니다. ");
			result = 2;
			return result;
		} else {

			// CRL_ -> X509CRL 타입 변환
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			CRL crl = cf.generateCRL(new ByteArrayInputStream(currentCertIssuerCRL.getRawData()));
			X509CRL X509crl = (X509CRL) crl; // java.security.cert.X509CRL

			// (a)CRL 획득
			// (1)대상인증서의 기관인증서발급자와 CRL의 기관인증서 발급자 일치 확인, 기관인증서 일련번호가 기관인증서 일련번호와 일치하는지 확인
			if (currentCert.getIssuerName() == currentCRL.getCa().getCertificate().getIssuerName()
					&& currentCert.getSerialNumber() == currentCRL.getCa().getCertificate().getSerialNumber()) {

				CA currentCertCaIssuer = caRepo.findOneByCaId(currentCert.getCa().getIssuerId()); // 대상인증서의 기관인증서 발급자

				System.out.println("대상인증서의 기관인증서 발급자 : " + currentCert.getIssuerName());
				System.out.println("CRL의 기관인증서 발급자 : " + currentCRL.getCa().getCertificate().getIssuerName());

				System.out.println("대상인증서의 기관인증서 일련번호 : " + currentCert.getSerialNumber());
				System.out.println("CRL 기관인증서 일련번호 : " + currentCRL.getCa().getCertificate().getSerialNumber());

			} else {
				result = 1;
				System.out.println("CRL 획득실패");
				return result;
			}

			// (2)유효기간 (현재시각이 NextUpdate보다 이후 일때 새로운 CRL을 획득하여, 새로운 CRL의 NextUpdate가 현재시각
			// 이후인지 검증)
			Date time = new Date();
			System.out.println("current time : " + time);
			System.out.println("CRL next update : " + X509crl.getNextUpdate());

			int compare = time.compareTo(X509crl.getNextUpdate()); // 현재시간-업데이트시간
			if (compare > 0) {
				result = 1;
				System.out.println("[CRL 유효기간 만료]");
				return result;

			} else {
				result = 0;
				System.out.println("[CRL 유효기간 검증 완료]");
			}

			// (b)발급자DN (대상인증서의 발급자DN과 CRL의 발급자 DN 일치여부 확인)
			byte[] certRawdata = currentCert.getRawData(); // Certificate_ → X509Certificate
			CertificateFactory certcf = CertificateFactory.getInstance("X.509");
			Certificate certificate = certcf.generateCertificate(new ByteArrayInputStream(certRawdata));

			CertificateFactory crlcf = CertificateFactory.getInstance("X.509"); // CRL_ → X509CRL
			// CRL crl_ = crlcf.generateCRL(new
			// ByteArrayInputStream(currentCRL.getRawData())); //대상인증서의 issuer CRL
			// CRL crl_ = crlcf.generateCRL(new
			// ByteArrayInputStream(currentCertIssuerCRL.getRawData()));
			CRL crl_ = crlcf.generateCRL(new ByteArrayInputStream(currentCertIssuerCRL.getRawData()));
			X509CRL x509crl = (X509CRL) crl_;

			String certSubjectDN = ((X509Certificate) certificate).getIssuerDN().getName();
			Principal crlIssuerDN = x509crl.getIssuerDN();

			if (crlIssuerDN.toString().equals(certSubjectDN)) {
				result = 0;
				System.out.println("current CRL issuer DN 과 current cert issuer DN 검증완료");
			} else {
				result = 1;
				System.out.println("current CRL issuer DN 과 current cert issuer DN 검증실패");
				return result;
			}

			// (c)CRL발급자에 대한 인증경로를 생성하고 검증 (상위기관 subject = 하위기관 Issuer)
			CA crlIssuerCA = caRepo.findOneByCaId(currentCRL.getCa().getIssuerId()); // 현재CRL기관의 발급자 임시

			List<CRL_> crlChain = new ArrayList<>();
			crlChain.add(currentCRL); // chain 저장

			while (currentCRL.getCa().getCaType() != CAType.ROOTCA) {
				System.out.println("검증하고자 하는 CRL의 발급자(issuer) :  " + currentCRL.getCrlIssuerName()); // 검증하고자 하는 CRL의
																										// 발급자(issuer)
				System.out.println("검증하고자 하는 CRL의 상위기관 소유자(subject) :  " + crlIssuerCA.getCaName()); // 검증하고자 하는 인증서의
																										// 상위기관
																										// 소유자(subject)

				// 상위인증서 끌어오는부분. Issuer 호출
				crlIssuerCA = caRepo.findOneByCaId(crlIssuerCA.getIssuerId());
				CRL_ issuerCRL = crlRepo.findOneByCrlId(crlIssuerCA.getCrlId());
				currentCRL = crlRepo.findOneByCrlId(crlIssuerCA.getCrlId());

				crlChain.add(currentCRL);

				System.out.println("검증하고자 하는 CRL의 상위기관 발급자(issuer) :  " + issuerCRL.getCrlIssuerName()); // 검증하고자 하는
																											// 인증서의 상위기관
																											// 발급자(issuer)
				System.out.println("검증하고자 하는 CRL의 상위기관의 상위기관 소유자(subject) :  " + crlIssuerCA.getCaName()); // 검증하고자 하는
																											// 인증서의
																											// 상위기관의
																											// 상위기간
																											// 소유자(subject)

				if (currentCRL.getCa().getCaType() == CAType.ROOTCA) {
					break;
				}
			}

			for (int i = 0; i < crlChain.size(); i++) {
				System.out.println("CRL " + crlChain.get(i).getCrlId());
			}

			byte[] crlRawdata = null;
			CA upperCA = null;
			for (int i = crlChain.size() - 1; i >= 0; i--) {
				// if (upperCA.getCaType()==CAType.ROOTCA){ // Endentity면 검증 할필요 x
				// (d)CRL 서명 검증
				crlRawdata = crlChain.get(i).getRawData(); // 최상위 기관부터 검증할 CRL rawdata

				CertificateFactory crlcf2 = CertificateFactory.getInstance("X.509"); // CRL_ → X509CRL 타입으로 변환
				CRL crl2_ = crlcf2.generateCRL(new ByteArrayInputStream(crlRawdata));
				X509CRL x509crl2 = (X509CRL) crl2_;

				try {
					upperCA = crlChain.get(i).getCa(); // root는 스스로의 key로 검증. 하위 CRL들은 상위 기관의 key로 검증
					x509crl2.verify(upperCA.getCertificate().getPublicKey());

					System.out.println("CRL 서명검증완료 ");
					result = 0;

				} catch (Exception e) {
					System.out.println("CRL 서명검증실패 ");
					result = 1;
					break;
				}
				// }//upperCA null check

				// (e)대상인증서의 일련번호 존재 여부 확인. 존재 시 reasoncode 입력
				// CA upperCA2 = caRepo.findOneByCaId(crlChain.get(i).getCa().getIssuerId());
				// 선택한 기관의 상위기관 CRL을 뒤져야 대상인증서의 취소내역 확인 가능
				// CRL_ upperCACRL = crlRepo.findOneByCrlId(upperCA2.getCrlId());

				for (int j = 0; j < crlChain.get(i).getRevokedCerts().size(); j++) {

					// BigIntger -> int
					int certint = cert.getSerialNumber().intValue();
					int revokedcetsint = crlChain.get(i).getRevokedCerts().get(j).getCertificateSerialNumber()
							.intValue();

					if (certint == revokedcetsint) { // 대상인증서가 검증할 CRL의 revoked list에 존재한다면 result=1 → break
						result = 1;
						return result;
					} else {
						result = 0;
					}
				} // revoked cert 유무 확인을 위한 loop
			} // crlChain loop

			// 대상인증서의 상위기관 인증서들중에 폐지된 인증서가 있는지 확인
			if (certChain != null) { // 인증서 검증시에만 기능함. CRL검증시에는 pass

				for (int i = 0; i < certChain.size(); i++) {

					CA issuer = caRepo.findOneByCaId(certChain.get(i).getIssuerId()); // 대상인증서의 경로에 존재하는 현재 인증서의 상위기관

					if (issuer.getCrlId() != 0) { // 대상인증서의 경로내에 기관들중에 CRL이 존재할 경우에만 해당 CRL의 폐기리스트 확인
						CRL_ issuerCrl = crlRepo.findOneByCrlId(issuer.getCrlId());

						for (int j = 0; j < issuerCrl.getRevokedCerts().size(); j++) {

							// BigIntger -> int
							int revokedCertSerial = issuerCrl.getRevokedCerts().get(j).getCertificateSerialNumber()
									.intValue();
							int currentCertSerialOnchain = certChain.get(i).getSerialNumber().intValue();
							if (revokedCertSerial == currentCertSerialOnchain) {

								result = 1;
								return result;
							}
						} // 해당 CRL 내 폐기리스트 loop
					} // CRL 존재여부 check
				} // 인증서체인 loop
			} // 상위기관인증서 폐지유무 check
		} // CRL 유무 check

		return result;
	}

	// crl : 인증서 검증시에는 발급자 CRL. CRL자체 검증시에는 검증할 CRL이 파라미터로 들어와야함
	public int validateCRLNew(int result, Certificate_ cert, List<Certificate_> certChain,
			Certificate_ currentCertInChain, CRL_ crl) throws CertificateException, CRLException, InvalidKeyException,
			NoSuchAlgorithmException, NoSuchProviderException, SignatureException {

		// (1)CRL획득
		CA currentCA = cert.getCa();
		CRL_ currentCRL = crl;
		CA issuer = caRepo.findOneByCaId(cert.getIssuerId());

		// CRL_ → X509CRL 타입 변환
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		CRL crltemp = cf.generateCRL(new ByteArrayInputStream(currentCRL.getRawData()));
		X509CRL X509crl = (X509CRL) crltemp; // java.security.cert.X509CRL

		// (2)유효기간
		Date time = new Date();
		// System.out.println("current time : " + time);
		// System.out.println("CRL next update : " + X509crl.getNextUpdate());

		int compare = time.compareTo(X509crl.getNextUpdate()); // 현재시간-업데이트시간
		if (compare > 0) {
			result = 1;
			System.out.println("CRL 유효기간 만료");

		} else {
			result = 0;
			System.out.println("CRL 유효기간 검증 완료");
		}

		// (3)대상인증서 발급자 DN = CRL발급자 DN 검증
		if (issuer.getCaType() != CAType.ROOTCA) {
			byte[] certRawdata = currentCA.getCertificate().getRawData(); // Certificate_→X509Certificate
			CertificateFactory certcf = CertificateFactory.getInstance("X.509");
			Certificate certificate = certcf.generateCertificate(new ByteArrayInputStream(certRawdata));

			CertificateFactory crlcf = CertificateFactory.getInstance("X.509"); // CRL_ →X509CRL 타
			CRL_ tempcrl = crlRepo.findOneByCrlId(issuer.getCrlId()); // DB에서 CRL발급자는 인증서기관이 아닌 상위기관으로 등록되어있음.

			CRL crl_ = crlcf.generateCRL(new ByteArrayInputStream((tempcrl.getRawData())));
			X509CRL x509crl = (X509CRL) crl_;

			String certIssuer = ((X509Certificate) certificate).getIssuerDN().getName();
			Principal crlIssuer = x509crl.getIssuerDN();

			System.out.println("CRL Issuer DN : " + crlIssuer.toString());
			System.out.println("Cert Issuer DN : " + certIssuer);

			if (certIssuer.equals(crlIssuer.toString())) {
				result = 0;
			} else {
				result = 1;
				return result;
			}
		}

		// (4)CRL 발급자 경로 검증 (인증서 검증. 인증서경로는 짧아짐)
		List<Certificate_> crlChain = new ArrayList<>();
		CA issuerCertTemp = caRepo.findOneByCaId(currentCertInChain.getIssuerId());
		crlChain.add(issuerCertTemp.getCertificate());

		while (issuerCertTemp.getCaType() != CAType.ROOTCA) {

			CA issuerTemp = caRepo.findOneByCaId(issuerCertTemp.getIssuerId());
			issuerCertTemp = issuerTemp;
			crlChain.add(issuerCertTemp.getCertificate());

			if (issuerCertTemp.getCaType() == CAType.ROOTCA) {
				break;
			}
		}

		// 인증서체인 순서 루트부터 정렬
		Collections.reverse(crlChain);

		byte[] certRawdata2 = null;// 서명검증할 인증서
		CA issuerCA = null;// 서명검증할 인증서 발급기관

		for (int i = 0; i < crlChain.size(); i++) {

			if (crlChain.get(i).getCa().getCaType() != CAType.ROOTCA) { // 루트 제외

				// (4-1)서명
				certRawdata2 = crlChain.get(i).getRawData(); // root부터 검증할 인증서
				CertificateFactory certCF = CertificateFactory.getInstance("X.509");
				Certificate certificateinCRL = certCF.generateCertificate(new ByteArrayInputStream(certRawdata2)); // 인증서
																													// 타입변환

				try {
					System.out.println("crlChain.get(i) ID " + crlChain.get(i).getCertId());
					issuerCA = caRepo.findOneByCaId(crlChain.get(i).getIssuerId()); // root는인증서는 스스로의 key로 검증. 하위 인증서들은
																					// 상위 인증서의 key로 검증
					System.out.println("issuerCA.getCertificate() ID " + issuerCA.getCertificate().getCertId());

					// certificateinCRL.verify(issuerCA.getCertificate().getPublicKey());
					certificateinCRL.verify(issuer.getCertificate().getPublicKey());

					result = 0;
					System.out.println("인증서 서명검증완료 ");

				} catch (Exception e) {
					System.out.println("인증서 서명검증실패 ");
					result = 1;
					break;
				}

				// (4-2)유효기간
				try {
					((X509Certificate) certificateinCRL).checkValidity(new Date()); // 현재시간과 유효기간의 비교

				} catch (CertificateExpiredException cee) { // 유효기간이 지난 경우
					result = 1;
					System.out.println("인증서 유효기간 만료");
					cee.printStackTrace();
					break;

				} catch (CertificateNotYetValidException cnyve) { // 유효기간이 아직 시작되지 않은 경우
					result = 1;
					System.out.println("유효기간이 개시되기 전의 RootCA 인증서"); // 에러메시지
					cnyve.printStackTrace();
					break;
				}
				System.out.println("인증서 유효기간 검증완료 ");

			}

			// (4-3)인증서 발급자DN

		}

		// (5)CRL 서명 검증
		byte[] crlRawdata = null;
		CA upperCA = caRepo.findOneByCaId(cert.getIssuerId());
		CRL_ crlForSignature = crlRepo.findOneByCrlId(cert.getCa().getCrlId()); // 대상CRL

		if ((cert.getCa().getCaType() != CAType.ROOTCA) || (cert.getCa().getCrlId() != 0)) { // Root거나 CRL없는경우는 탈필요 X

			System.out.println("cert ID : " + cert.getCertId());
			System.out.println("ca ID : " + cert.getCa().getCaId());
			System.out.println("crlforsignature Issuer ID : " + upperCA.getCaId());

			// crlRawdata = crlForSignature.getRawData();
			crlRawdata = crl.getRawData();
			CertificateFactory crlcf2 = CertificateFactory.getInstance("X.509"); // CRL_ → X509CRL
			CRL crl2_ = crlcf2.generateCRL(new ByteArrayInputStream(crlRawdata));
			X509CRL x509crl2 = (X509CRL) crl2_;

			try {
				x509crl2.verify(cert.getCa().getCertificate().getPublicKey());
				// x509crl2.verify(upperCA.getCertificate().getPublicKey());

				System.out.println("CRL 서명검증완료 ");
				result = 0;

			} catch (Exception e) {

				System.out.println("CRL 서명검증실패 ");
				result = 1;
				return result;
			}

		}

		// (6)대상인증서 CRL 폐지여부
		for (int j = 0; j < crl.getRevokedCerts().size(); j++) {

			int certint = cert.getSerialNumber().intValue();// bigIntger -> int
			int revokedcetsint = crl.getRevokedCerts().get(j).getCertificateSerialNumber().intValue();

			if (certint == revokedcetsint) { // 대상인증서가 검증할 CRL의 revoked list에 존재한다면 result=1 → break
				result = 1;
				return result;
			} else {
				result = 0;
			}
		}

		return result;
	}

	public int validateCRLNewNew(int result, Certificate_ cert, List<Certificate_> certChain, Certificate_ certInChain)
			throws CertificateException, CRLException, InvalidKeyException, NoSuchAlgorithmException,
			NoSuchProviderException, SignatureException {

		CA issuer = caRepo.findOneByCaId(certInChain.getIssuerId()); // 대상 인증서 발급자
		CA currentCA = certInChain.getCa();
		CRL_ crl = crlRepo.findOneByCrlId(issuer.getCrlId());
		if (crl == null) {
			return 0;
		}

		// CRL_ → X509CRL 타입 변환
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		CRL crltemp = cf.generateCRL(new ByteArrayInputStream(crl.getRawData()));
		X509CRL X509crl = (X509CRL) crltemp; // java.security.cert.X509CRL

		// (1)유효기간
		Date time = new Date();

		int compare = time.compareTo(X509crl.getNextUpdate());
		if (compare < 0) {
			result = 0;
			System.out.println("CRL 유효기간 검증 완료");
		} else {
			result = 1;
			System.out.println("CRL 유효기간 만료");
			return result;
		}

		// (2)발급자 DN (==대상 인증서 발급자DN)
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

			System.out.println("CRL Issuer DN : " + crlIssuer.toString());
			System.out.println("Cert Issuer DN : " + certIssuer);

			if (certIssuer.equals(crlIssuer.toString())) {
				result = 0;
			} else {
				result = 1;
				return result;
			}
		}

		// (3)CRL발급자 경로검증(인증서경로 검증. CRL발급자부터 타고 올라가.
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
			result = crtService.validateCertNewNew(result, cert, crlChain, null);

		}

		// (4)CRL서명검증
		byte[] crlRawdata = null;
		CA upperCA = caRepo.findOneByCaId(cert.getIssuerId());

		// crlRawdata = crlForSignature.getRawData();
		crlRawdata = crl.getRawData();
		CertificateFactory crlcf2 = CertificateFactory.getInstance("X.509"); // CRL_ → X509CRL
		CRL crl2_ = crlcf2.generateCRL(new ByteArrayInputStream(crlRawdata));
		X509CRL x509crl2 = (X509CRL) crl2_;

		try {
			x509crl2.verify(issuer.getCertificate().getPublicKey());
			// 인증서는 상위기관(발급자)의 공개키로 인증을 하고, CRL은 발급자가 상위기관이 아닌 해당기관 이므로 서명검증시 상위기관 공개키로 검증
			// 하면 안됨

			System.out.println("CRL 서명검증완료 ");
			result = 0;

		} catch (Exception e) {

			System.out.println("CRL 서명검증실패 ");
			result = 1;
			return result;
		}

		// }

		// (5)대상인증서 CRL 폐지여부
		for (int j = 0; j < crl.getRevokedCerts().size(); j++) {

			// bigIntger -> int
			int certint = cert.getSerialNumber().intValue();
			int revokedcetsint = crl.getRevokedCerts().get(j).getCertificateSerialNumber().intValue();

			if (certint == revokedcetsint) { // 대상인증서가 검증할 CRL의 revoked list에 존재한다면
				result = 1;
				return result;
			} else {
				result = 0;
			}
		}

		return result;
	}

	public void downloadCRL(int crlId, CRL_ crl, byte[] rawdata) throws FileNotFoundException { // 파일업로드
		String fileName = "crl" + crlId;
		FileOutputStream fos = new FileOutputStream(new File(fileName + ".crl"));

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

	}

}