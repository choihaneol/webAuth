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
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
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
public class CertServiceImpl implements CertService {
	
	
	
	@Autowired
	private CRLService crlService;


	@Autowired
	private CARepository caRepository;

	
	@Autowired
	private CertRepository crtRepository;

	@Autowired
	private CRLRepository crlRepository;
	
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
	public void generateCert(String userName, String company, String email, CAType catype, CA issuer) // 인증서발급
			throws InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException,
			SignatureException, OperatorCreationException, CertificateException, InvalidKeySpecException {
 

		// 선택된 기관의id 에서 Certificate가장 최근 Id의 userName, subjectname, compnay, email 찾아서
		// subject에 넣어
		// 선택 기관 체크 > 기관에 따라 ICA or End entity 인증서 생성 ( key생성 > CSR생성> 새로운 인증서 생성 )
		
		generateSelfSignedX509CACertificate(userName, company, email, catype, issuer); // 인증서 생성시작


		return;
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
		
		//byte[] sig = crt.getCaDigitalSigniture();
		// System.out.println("sigggggggggg" + sig);
		
		Certificate_ newCert = crtRepository.save(crt);
		newCa.setCertificate(newCert);
		caRepository.save(newCa);
		
		System.out.println(cert);
 
		return cert;
	}
	
	


	
	
	@Override
	public void addBouncyCastleAsSecurityProvider() {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	

	@Override
	public int validateCertNew(Certificate_ cert, int result, CA certIssuer)
			throws CertificateException, InvalidKeyException,
			NoSuchAlgorithmException, NoSuchProviderException, SignatureException, CRLException {
		
		CA currentCA = cert.getCa();
		List<Certificate_> certChain = new ArrayList<>();
 

		
		// (1)경로획득
		certChain.add(cert); // 대상인증서
		
		CA issuertmp = caRepository.findOneByCaId(cert.getIssuerId()); // 임시객체
		certChain.add(issuertmp.getCertificate());
		
		while (currentCA.getCaType() != CAType.ROOTCA) { // self sign까지 올라가기
			System.out.println("대상 인증서의 발급자(issuer) :  " + cert.getIssuerName());
			System.out.println("대상 인증서의 상위기관 소유자(subject) :  " + issuertmp.getCaName());
			
			issuertmp = caRepository.findOneByCaId(issuertmp.getIssuerId()); // issuer의 issuer를 불러줘야 되는데 issuer의 자기자신을 불러주고 있어서 무한루프 도는것였음.
			currentCA = caRepository.findOneByCaId(issuertmp.getIssuerId());
			
			certChain.add(currentCA.getCertificate());
			
			if (currentCA.getCaType() == CAType.ROOTCA) {
				break;
			}
		}
		
		
		// 인증서체인 순서 루트부터 정렬
		Collections.reverse(certChain);
		
		for (int i = 0; i < certChain.size(); i++) {
			CA certissuer = caRepository.findOneByCaId(certChain.get(i).getIssuerId());
 			// System.out.println("대상 인증서의 발급자(issuer) : " + certChain.get(i).getIssuerName());
			// System.out.println("대상 인증서의 상위기관 소유자(subject) : " + certissuer.getCaName());
		}
		
		
		byte[] certRawdata = null;// 서명검증할 인증서
		CA issuerCA = null;// 서명검증할 인증서 발급기관
		
		for (int i = 0; i < certChain.size(); i++) {
			
			if (certChain.get(i).getCa().getCaType() != CAType.ROOTCA) { //ROOT제외
				
	 			// (2)서명검증
			certRawdata = certChain.get(i).getRawData(); // root부터 검증할 인증서
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			Certificate certificate = cf.generateCertificate(new ByteArrayInputStream(certRawdata)); // 인증서 타입변환
			try {
				issuerCA = caRepository.findOneByCaId(certChain.get(i).getIssuerId()); // root는인증서는 스스로의 key로 검증. 하위인증서들은 상위 인증서의 key로 검증
				certificate.verify(issuerCA.getCertificate().getPublicKey());
				result = 0;

				
				// System.out.println("-issuerCA의 인증서 ID : " + issuerCA.getCertificate().getCertId());
				// System.out.println("-currentCA의 인증서 ID : " + certChain.get(i).getCertId());
				System.out.println("[인증서 서명검증완료] ");
				
			} catch (Exception e) {
				System.out.println("[인증서 서명검증실패] ");
				result = 1;
				break;
			}
			
			
			
			
			// (3)유효기간
			try {
				((X509Certificate) certificate).checkValidity(new Date()); // 현재시간과 유효기간의 비교
				
			} catch (CertificateExpiredException cee) { // 유효기간이 지난 경우 에러메시지
				result = 1;
				System.out.println("[인증서 유효기간 만료]");
				cee.printStackTrace();
				break;
				
			} catch (CertificateNotYetValidException cnyve) { // 유효기간이 아직 시작되지 않은 경우
				result = 1;
				System.out.println("[유효기간이 개시되기 전의 RootCA 인증서]"); // 에러메시지
				cnyve.printStackTrace();
				break;
			}
			System.out.println("[인증서 유효기간 검증완료] ");
			
			
			
			// (4)CRL 확인
			CA issuer = caRepository.findOneByCaId(cert.getIssuerId());
			CRL_ issuerCRL = crlRepository.findOneByCrlId(issuer.getCrlId());
			// System.out.println("대상인증서의 CRL ID : " + cert.getCa().getCrlId());
			System.out.println("대상인증서의 CRL ID : " + issuer.getCrlId());
			if (issuer.getCrlId() != 0) { // 발급자의 CRL존재 할 경우에만 CRL검증 거친다. 폐지리스트는(DB에서는) 대상인증기관이 아닌 발급기관의 CRL에 저장되어 있으므로.
				
				// if (cert.getCa().getCrlId() != 0 ) { // 발급자의 CRL존재 할 경우에만 CRL검증 거친다.
				// 폐지리스트는(DB에서는) 대상인증기관이 아닌 발급기관의 CRL에 저장되어 있으므로.
				result = crlService.validateCRLNew(result, cert, certChain, certChain.get(i), issuerCRL); // cert:대상인증서,certChain.get(i):인증서경로 내에 인증서
				if (result == 1) { // 검증 실패시 리턴
					return result;
				}
			}
			//인증서검증과 CRL검증함수를 양쪽에서 호출하면 인증서검증 함수에서 CRL 검증 함수 호출하는 부분 밑으롤 안탐 ?!!!!
			//로직?.?
			
			
			// (5)발급자DN
 			String certSubject = ((X509Certificate) certificate).getIssuerDN().getName(); // 검증하고자 하는 인증서의 IssuerDN
			String uppercertIssuer = ((X509Certificate) certificate).getIssuerDN().getName(); // 상위기관인서의 subjectDN
			
			if (certSubject.equals(uppercertIssuer)) { // 상위 인증기관 인증서 subject와 검증대상 인증서 issuer 바교
				result = 0;
	 
				System.out.println("[발급자DN 검증완료] ");
				
			} else {
				result = 1;
				System.out.println("발급자 DN 검증 실패");
				break;
			}
			
			
			}//ROOT제외
			
		}
		
		
		
		
		// 상위기관 인증서중 폐지된 인증서 존재시 하위기관 인증서 모두 무효처리
		if (certChain != null) { // 인증서 검증시에만 기능함. CRL검증시에는 pass
			 	
			for (int i = 0; i < certChain.size(); i++) {
				
				CA issuerCheckCA = caRepository.findOneByCaId(certChain.get(i).getIssuerId()); // 대상인증서의 경로에 존재하는 현재 인증서의 상위기관
				 
				if (issuerCheckCA.getCrlId() != 0) { // 대상인증서의 경로내에 기관들중에 CRL이 존재할 경우에만 해당 CRL의 폐기리스트 확인
					
					CRL_ issuerCrl = crlRepository.findOneByCrlId(issuerCheckCA.getCrlId());
					 
					
					for (int j = 0; j < issuerCrl.getRevokedCerts().size(); j++) {
						
					 	
						// BigIntger -> int
						int revokedCertSerial = issuerCrl.getRevokedCerts().get(j)
								.getCertificateSerialNumber().intValue();
						int currentCertSerialOnchain = certChain.get(i).getSerialNumber().intValue();
					
						if (revokedCertSerial == currentCertSerialOnchain) {
							
 							result = 1;
							return result;
						}
						
					} // 해당 CRL 내 폐기리스트 loop
					
				} // CRL 존재여부 check
				
			} // 인증서체인 loop
			
		} // CRL 유무 check
		
		return result;
	}
	
	
	
	
	@Override
	public int validateCertNewNew(int result, Certificate_ cert,  List<Certificate_> certChain, CA certIssuer)
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
				result = 0;
				
				//System.out.println("서명검증 할 발급자 ID : " + issuerCA.getCertificate().getCertId());
				//System.out.println("서명검증 받을 인증서 ID : " + certChain.get(i).getCertId());
				System.out.println("[인증서 서명검증완료] ");
				
			} catch (Exception e) {
				System.out.println("[인증서 서명검증실패] ");
				result = 1;
				break;
			}
			
			
			
			
			//(3)유효기간
			try {
				((X509Certificate) certificate).checkValidity(new Date()); // 현재시간과 유효기간의 비교
				result = 0;
			} catch (CertificateExpiredException cee) { //유효기간이 지난 경우 에러메시지
				result = 1;
				System.out.println("[인증서 유효기간 만료]");
				cee.printStackTrace();
				break;
				
			} catch (CertificateNotYetValidException cnyve) { // 유효기간이 아직 시작되지  않은 경우 에러메시지
				result = 1;
				System.out.println("[유효기간이 개시되기 전의 RootCA 인증서]");
				cnyve.printStackTrace();
				break;
			}
			System.out.println("[인증서 유효기간 검증완료] ");
			
			
			
			
		    //(4)CRL확인
			if (certChain.get(i).getCa().getCaType() != CAType.ROOTCA) { // Root아닐시에만 CRL검증
				result = crlService.validateCRLNewNew(result, cert, certChain, certChain.get(i)); //검증 certChain.get(i) 기준으로 돌아감

				if (result == 1) { // 검증 실패시 리턴
					return result;
				}
			}
			


			//(5)발급자 DN
			String certSubject = ((X509Certificate) certificate).getIssuerDN().getName(); //검증하고자 하는 인증서의 IssuerDN
			String uppercertIssuer = ((X509Certificate) certificate).getIssuerDN().getName(); // 상위기관인서의  subjectDN
			
			
			if (certSubject.equals(uppercertIssuer)) { //상위 인증기관 인증서 subject와 검증대상 인증서 issuer 바교
				result = 0;
				System.out.println("[발급자DN 검증완료] ");
				
			} else {
				result = 1;
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
			
		} // CRL 유무 check
			
		return result;
	}
	
	
	
	
	public void downloadCert(int certId, Certificate_ cert, byte[] rawdata) throws FileNotFoundException { // 파일업로드
 		String fileName = "cert" + certId;
		FileOutputStream fos = new FileOutputStream(new File(fileName + ".der"));
		// FileOutputStream fos = new FileOutputStream(new File("C:\\Users" + fileName)
		// );
 		
		try {
			fos.write((rawdata));
 		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
 		} // 파일로저장
		try {
			fos.close();
 		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
 		}
		
 	}
}