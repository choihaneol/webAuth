package com.example.pkiDemo.service;


import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
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
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.pkiDemo.entity.CA;
import com.example.pkiDemo.entity.CAType;
import com.example.pkiDemo.entity.CRL_;
import com.example.pkiDemo.entity.Certificate_;
import com.example.pkiDemo.repository.CARepository;
import com.example.pkiDemo.repository.CRLRepository;
import com.example.pkiDemo.repository.CertRepository;


@Service
public class RestCertServiceImpl implements RestCertService{
	
	@Autowired
	private CRLService crlService;

	@Autowired
	private CARepository caRepository;

	@Autowired
	private CertRepository crtRepository;

	@Autowired
	private CRLRepository crlRepository;

	@Autowired
	private RestCRLService restCRLService;


	
	@Override
	public void saveCA(CA ca) { // 기관 저장
		caRepository.save(ca);
	}
	
	@Override
	public List<CA> getList() { // 기관 목록
		return caRepository.findAll();
	}
	
	
	@Override
	public Certificate_ getCert(int certId) { // 인증서조회
		return crtRepository.findOneByCertId(certId);
	}

	
	@Override
	public void saveCert(Certificate_ certificate) { // 인증서저장
		crtRepository.save(certificate);
	}


	@Override
	public Certificate generateSelfSignedX509RootCertificate()
			throws InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException,
			SignatureException, OperatorCreationException, CertificateException {
		addBouncyCastleAsSecurityProvider();

		String rootCA = "CN = ROOTCA";

		// generate a key pair
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
		keyPairGenerator.initialize(2048, new SecureRandom());
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		// build a certificate generator
		SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
		X509v3CertificateBuilder builder = new X509v3CertificateBuilder(new X500Name(rootCA), // Issuer
				BigInteger.valueOf(System.currentTimeMillis()),
				new Date(System.currentTimeMillis()),
				new Date(System.currentTimeMillis() + (4 * 365) * 24 * 60 * 60 * 1000), new X500Name(rootCA),
				subPubKeyInfo); // Subject

		ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").setProvider(new BouncyCastleProvider())
				.build(keyPair.getPrivate());
		System.out.println("signer    : " + signer);

		X509CertificateHolder holder = builder.build(signer);
		System.out.println("signer    : " + signer.getSignature());

		Certificate cert = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider())
				.getCertificate(holder);

		// RootCA DB저장, 주임님 수정
		CA ca = new CA();

		ca.setCaName(rootCA);
		ca.setCaType(CAType.ROOTCA);
		ca.setIssuerId(1);
		// ca.setCertId(1);
		CA newCa = caRepository.save(ca);

		// 인증서 DB저장
		Certificate_ crt = new Certificate_();

		crt.setCa(newCa);
		crt.setSerialNumber(holder.getSerialNumber());
		crt.setIssuerName("CN = ROOTCA");
		crt.setIssuerId(1); // rootCA니까 항상 1번
		crt.setExpiredDateStart(holder.getNotBefore());
		crt.setExpiredDateEnd(holder.getNotAfter());
		crt.setSubjectName(rootCA);
		crt.setPublicKey(keyPair.getPublic());
		crt.setPrivateKey(keyPair.getPrivate());
		crt.setCaDigitalSigniture(holder.getSignature());
		// crt.setRawData((Certificate) cert);
		crt.setRawData(cert.getEncoded());
		crt.setUserName("RootCA");
		crt.setCompany("Fescaro");
		crt.setEmail("Fescaro@fescaro.com");

		Certificate_ newCert = crtRepository.save(crt);
		newCa.setCertificate(newCert);
		// newCa.setCertificate(newCert);
		caRepository.save(newCa);
		System.out.println(cert);

		return cert;
	}


	
	
	@Override
	public Certificate generateCert(String userName, String company, String email, CAType catype, CA issuer) // 인증서발급
			throws InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException,
			SignatureException, OperatorCreationException, CertificateException, InvalidKeySpecException {
 
		// 선택된 기관의id 에서 Certificate가장 최근 Id의 userName, subjectname, compnay, email 찾아서 subject에 넣어
		// 선택 기관 체크 > 기관에 따라 ICA or End entity 인증서 생성 ( key생성 > CSR생성> 새로운 인증서 생성 )
		Certificate cert = generateSelfSignedX509CACertificate(userName, company, email, catype, issuer); // 인증서 생성시작

		return cert;
	}


	
	
	
	@Override
	public Certificate generateSelfSignedX509CACertificate(String userName, String company, String email,
			CAType issuerCaType, CA issuer)
			throws InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException,
			SignatureException, OperatorCreationException, CertificateException, InvalidKeySpecException {
		addBouncyCastleAsSecurityProvider();

		String issuerStr = issuer.getCertificate().getSubjectName();

		String subject = "EMAILADDRESS=" + email + ", O=" + company + ", CN=" + userName;

		 
		Certificate_ issuerCert = issuer.getCertificate();

		// generate a key pair
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
		keyPairGenerator.initialize(2048, new SecureRandom());
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		// build a certificate generator
		SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
		X509v3CertificateBuilder builder = new X509v3CertificateBuilder(new X500Name(issuerStr), // Issuer
				BigInteger.valueOf(System.currentTimeMillis()),
				new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000),
				new Date(System.currentTimeMillis() + (4 * 365) * 24 * 60 * 60 * 1000), new X500Name(subject),
				subPubKeyInfo); // Subject

		// signiture
		ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").setProvider(new BouncyCastleProvider())
				.build(issuerCert.getPrivateKey()); // 개인키는 인증서 생성할때, 공개키는 인증할때 사용

		X509CertificateHolder holder = builder.build(signer);

		Certificate cert = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider())
				.getCertificate(holder);

		CAType catype;
		if (issuerCaType == CAType.ROOTCA) { // 발급기관이 Root면, CA타입 ICA로 저장
			catype = CAType.ICA;
		} // else if (catype == CAType.ICA) { // 발급기관이 ICA이면, CA타입 end-entity로 저장
		else if (issuerCaType == CAType.ICA) {
			catype = CAType.ENDENTITY;
		} else {
			return null;
		}

		// End-entity DB저장
		CA ca = new CA();

		ca.setCaType(catype);
		ca.setIssuerId(issuer.getCaId());
		ca.setCaName(subject);
		CA newCa = caRepository.save(ca);

		// 인증서 DB저장
		Certificate_ crt = new Certificate_();

		crt.setCa(newCa);
		crt.setSerialNumber(holder.getSerialNumber());
		crt.setIssuerName(issuerCert.getSubjectName());
		crt.setIssuerId(issuerCert.getCertId());
		crt.setExpiredDateStart(holder.getNotBefore());
		crt.setExpiredDateEnd(holder.getNotAfter());
		crt.setSubjectName(subject);
		crt.setPublicKey(keyPair.getPublic());
		crt.setPrivateKey(keyPair.getPrivate());
		crt.setCaDigitalSigniture(holder.getSignature());
		// byte[] signiture = holder.getSignature();
		// System.out.println("signiture signiture : " + signiture ); 복호화??
		// https://www.phpschool.com/gnuboard4/bbs/board.php?bo_table=qna_other&wr_id=113178
		// crt.setRawData((Certificate) cert);
		crt.setRawData(cert.getEncoded());
		crt.setUserName(userName); // userName 변수로 바꿔
		crt.setCompany(company); // company 변수로 바꿔
		crt.setEmail(email);// email 변수로 바꿔

		// byte[] sig = crt.getCaDigitalSigniture();
		// System.out.println("sigggggggggg" + sig);

		Certificate_ newCert = crtRepository.save(crt);
		newCa.setCertificate(newCert);
		caRepository.save(newCa);

		System.out.println(cert);
		System.out.println("인증서 생성 완료");

		return cert;
	}
	
	
	@Override
	public void addBouncyCastleAsSecurityProvider() {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	
	@Override
	public boolean validateCertNewNew(boolean result, Certificate_ cert,  List<Certificate_> certChain, CA certIssuer)
			throws CertificateException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
			SignatureException, CRLException { //경로만 파라미터로 넣어주면 돌아감
		
		// 인증서체인 순서 루트부터 정렬
		Collections.reverse(certChain);
		
 
		
		
		byte[] certRawdata = null;// 서명검증할 인증서
		CA issuerCA = null;// 서명검증할 인증서 발급기관
		for (int i = 0; i < certChain.size(); i++) {
			
		//(2)서명검증
			certRawdata = certChain.get(i).getRawData(); // root부터 검증할 인증서
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			Certificate certificate = cf.generateCertificate(new ByteArrayInputStream(certRawdata)); // 인증서 타입변환
			try {
				issuerCA = caRepository.findOneByCaId(certChain.get(i).getIssuerId()); // root는인증서는 스스로의 key로 검증. 하위인증서들은 상위 인증서의 key로 검증
				certificate.verify(issuerCA.getCertificate().getPublicKey());
				result = true;

				//System.out.println("서명검증 할 발급자 ID : " + issuerCA.getCertificate().getCertId());
				//System.out.println("서명검증 받을 인증서 ID : " + certChain.get(i).getCertId());
				System.out.println("[인증서 서명검증완료] ");

			} catch (Exception e) {
				System.out.println("[인증서 서명검증실패] ");
				result = false;
				break;
			}
			
			
			
			
			//(3)유효기간
			try {
				((X509Certificate) certificate).checkValidity(new Date()); // 현재시간과 유효기간의 비교
				result = true;
			} catch (CertificateExpiredException cee) { //유효기간이 지난 경우 에러메시지
				result = false;
				System.out.println("[인증서 유효기간 만료]");
				cee.printStackTrace();
				break;
				
			} catch (CertificateNotYetValidException cnyve) { // 유효기간이 아직 시작되지  않은 경우 에러메시지
				result = false;
				System.out.println("[유효기간이 개시되기 전의 RootCA 인증서]");
				cnyve.printStackTrace();
				break;
			}
			System.out.println("[인증서 유효기간 검증완료] ");
			
			
			
			
		    //(4)CRL확인
			if (certChain.get(i).getCa().getCaType() != CAType.ROOTCA) { // Root아닐시에만 CRL검증
				result = restCRLService.validateCRLNewNew(result, cert, certChain, certChain.get(i)); //검증 certChain.get(i) 기준으로 돌아감

				if (result == false) { // 검증 실패시 리턴
					return result;
				}
			}
			

		//(5)발급자 DN
			String certSubject = ((X509Certificate) certificate).getIssuerDN().getName(); //검증하고자 하는 인증서의 IssuerDN
			String uppercertIssuer = ((X509Certificate) certificate).getIssuerDN().getName(); // 상위기관인서의  subjectDN

if (certSubject.equals(uppercertIssuer)) { //상위 인증기관 인증서 subject와 검증대상 인증서 issuer 바교
				result = true;
				System.out.printf("current certSubject DN : %s%n ", certSubject);
				System.out.printf("upper certIssuer DN : %s%n", uppercertIssuer);
				System.out.println("[발급자DN 검증완료] ");

} else {
				result = false;
				System.out.println("발급자 DN 검증 실패");
				return result;
			}						

		
		}
		
		
		
		// (6)상위기관 폐지여부 확인
		if (certChain != null) { //인증서 검증시에만 기능함. CRL검증시에는 pass
			System.out.println("대상인증서의 상위기관 인증서들중에 폐지된 인증서가 있는지 확인");
			System.out.println("대상인증서 일련번호 : " + cert.getSerialNumber());

			for (int i = 0; i < certChain.size(); i++) {

				CA issuerCheckCA = caRepository.findOneByCaId(certChain.get(i).getIssuerId()); //대상인증서의 경로에 존재하는 현재 인증서의 상위기관
				System.out.println("대상인증서의 경로에 존재하는 현재 인증서번호 : " + certChain.get(i).getCertId());
				System.out.println("대상인증서의 경로에 존재하는 현재 인증서의 상위기관번호 : " + certChain.get(i).getIssuerId());
				System.out.println("대상인증서의 경로에 존재하는 현재 인증서의 CRL번호 : " + issuerCheckCA.getCrlId());

if (issuerCheckCA.getCrlId() != 0) { //대상인증서의 경로내에 기관들중에 CRL이 존재할 경우에만 해당 CRL의 폐기리스트 확인

					CRL_ issuerCrl = crlRepository.findOneByCrlId(issuerCheckCA.getCrlId());
					System.out.printf("CRL %d번의 폐기된 인증서 개수:%d %n ", issuerCheckCA.getCrlId(),
							issuerCrl.getRevokedCerts().size());

					for (int j = 0; j < issuerCrl.getRevokedCerts().size(); j++) {

						// 대상인증서의 경로에 기관에 CRL 존재할 경우에만, 대상인증서의 경로에 존재하는 현재기관의 CRL의 serial number와 해당CRL의 폐기리스트 비교
						System.out.println(" 대상인증서의 경로에 존재하는 현재 인증서의 CRL 폐기 리스트 : "
								+ issuerCrl.getRevokedCerts().get(j).getCertificateSerialNumber());
						System.out.println("대상인증서의 경로에 존재하는 현재 인증서 일련번호 : " + certChain.get(i).getSerialNumber());


						/*// BigIntger -> int
						int revokedCertSerial = issuerCrl.getRevokedCerts().get(j).getCertificateSerialNumber()
								.intValue();
						int currentCertSerialOnchain = certChain.get(i).getSerialNumber().intValue();
​
						if (revokedCertSerial == currentCertSerialOnchain) {
​
							System.out.println("상위 기관내 취소된 폐기리스트와 일치!!!!!");
							result = 1;
							return result;
						}*/
						
						//CRL 타입으로 변환
						byte[] issuerCrlRawdata = issuerCrl.getRawData();
						CertificateFactory crlcf = CertificateFactory.getInstance("X.509"); // CRL_ → X509CRL 타입으로 변환
						CRL crl = crlcf.generateCRL(new ByteArrayInputStream(issuerCrlRawdata));
						X509CRL x509crl2 = (X509CRL) crl;
						
						//certificate 타입으로 변환
						certRawdata = certChain.get(i).getRawData();
						CertificateFactory cf = CertificateFactory.getInstance("X.509");
						Certificate certToCompare = cf.generateCertificate(new ByteArrayInputStream(certRawdata));
									
						
						boolean comparing = x509crl2.isRevoked(certToCompare);

						// 폐지여부 확인
						if (comparing){
							System.out.println("해당 인증서의 상위기관 중 폐지된 인증서 혹은 기관이 존재 합니다.");
							result = false;
							return result;
						} else {
							System.out.println("해당 인증서 유효(상위기관 폐지여부 검증)");
							result = true;
						}

					} // 해당 CRL 내 폐기리스트 loop

				} // CRL 존재여부 check

			} // 인증서체인 loop

		} // CRL 유무 check
		
		
		
		return result;
	}
	
	
	
	
	public Certificate downloadCert(int certId, Certificate_ cert, byte[] rawdata) throws FileNotFoundException, CertificateException { // 파일업로드
		System.out.println("다운로드 시작");
		String fileName = "cert" + certId;
		FileOutputStream fos = new FileOutputStream(new File(fileName + ".der"));

		// Certificate_→X509Certificate 타입 변환
		CertificateFactory certcf = CertificateFactory.getInstance("X.509");
		Certificate certToDownload = certcf.generateCertificate(new ByteArrayInputStream(rawdata));


		try {
			fos.write((rawdata));
			System.out.println("인증서 다운로드가 완료 되었으니 해당폴더를 확인하세요.");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("예외상황 발생");
		} // 파일로저장
		try {
			fos.close();
			System.out.println("인증서 다운로드 후 파일 닫기 완료.");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("예외상항 발생");
		}
		return certToDownload;
	}

}
