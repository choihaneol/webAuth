package com.example.pkiDemo.controller;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.pkiDemo.entity.CA;
import com.example.pkiDemo.entity.CAType;
import com.example.pkiDemo.entity.Certificate_;
import com.example.pkiDemo.entity.RevokedCertificate;
import com.example.pkiDemo.repository.CARepository;
import com.example.pkiDemo.repository.CertRepository;
import com.example.pkiDemo.service.RestCRLService;
import com.example.pkiDemo.service.RestCertService;

@RestController
@RequestMapping(path = "/certificate")
public class RestCertController {

	@Autowired
	private CARepository caRepository;

	@Autowired
	private CertRepository crtRepository;

	// REST
	@Autowired
	private RestCertService restCertService;

	@Autowired
	private RestCRLService restCRLService;

	
	
	// 기관목록 조회
	@GetMapping(path = "/list", produces = "application/json")
	// produces, consumes : specify the mediatype attributes for the API
	public List<CA> getList() throws InvalidKeyException, IllegalStateException, NoSuchProviderException,
			NoSuchAlgorithmException, SignatureException, OperatorCreationException, CertificateException {

		// checkRootCA(); // RootCA 여부 확인

		return restCertService.getList();
	}

	
	
	
	
	// 루트생성
	public void checkRootCA() throws InvalidKeyException, IllegalStateException, NoSuchProviderException,
			NoSuchAlgorithmException, SignatureException, OperatorCreationException, CertificateException {
		CA ca = caRepository.findOneByCaType(CAType.ROOTCA); // 주임님 수정
		if (ca == null) {

			// RootCA생성
			java.security.cert.Certificate cert = restCertService.generateSelfSignedX509RootCertificate();
		
		} else {
			System.out.println(ca);
		}
		return;
	}

	
	
	
	
	// 인증서 조회
	@GetMapping(path = "/{id}", produces = "application/json")
	// produces, consumes : specify the mediatype attributes for the API
	public Certificate_ getCert(@PathVariable int id) {

		return restCertService.getCert(id);
	}
	
	
	
	
	

	//인증서 등록
		@PostMapping("/register")
		public Certificate register(@RequestBody Certificate_ request)
				throws InvalidKeyException, IllegalStateException, NoSuchProviderException,
				NoSuchAlgorithmException, SignatureException, OperatorCreationException,
				CertificateException, InvalidKeySpecException{
		
			CA issuer = caRepository.findOneByCaId(request.getCa().getIssuerId());
			Certificate cert = null;
			
			if (issuer.getCaType() == CAType.ROOTCA || issuer.getCaType() == CAType.ICA) {

				cert = restCertService.generateCert(request.getUserName(), request.getCompany(),
						request.getEmail(), issuer.getCaType(), issuer);
				
			} else if (issuer.getCaType() == CAType.ENDENTITY) {
				System.out.println("인증서 발급이 불가합니다.");
			}
			return cert;
		}
	
	
	
		//인증서 폐지
		//@PostMapping("/delete/{certId}")
		@GetMapping(path ="/delete/{certId}", produces = "application/json")
		//public  List<RevokedCertificate> delete(@RequestBody int certId)
		public boolean delete(@PathVariable int certId)
				throws NoSuchAlgorithmException, NoSuchProviderException,
				OperatorCreationException, CRLException, CertificateException,
				ClassCastException, IOException{
			
			//certId로 caId 조회 -> caId로 crlId 조회 -> Null이면 생성하고 Null아니면 CRL에 폐기인증서 추가 -> 모달창
			
			Certificate_ cert = crtRepository.findOneByCertId(certId);		
			CA ca = cert.getCa();
			CAType caType = ca.getCaType();
			
			int issuerId = ca.getIssuerId();
			String issuerName = cert.getIssuerName();
			CA issuerCA = caRepository.findOneByCaId(issuerId);		
			int issuerCRLID = issuerCA.getCrlId();

			if (caType == CAType.ROOTCA) { // RootCA면 삭제 불가
				System.out.println("해당 인증서와 인증기관은 삭제 할 수 없습니다. (Root기관은 CRL이 존재하지 않습니다.)");		
		        return false;
			}else {
				
				if (issuerCRLID == 0) { // CRL없으면, CRL생성 -> 폐지인증서 추가
					System.out.println("CRL이 존재하지 않습니다. CRL생성후 인증서를 폐기하세요.");
					restCRLService.generateICACRL(certId, issuerId, issuerName, caType);
				} else { // CRL존재 -> 폐지인증서만 추가
					System.out.println("CRL이 존재합니다. 인증서만 폐기하세요. ");
					restCRLService.revokeCertificate(certId, issuerId, issuerName, caType);
				}	
			}
		
			// 인증서 폐기 후 인증서폐지목록으로 되돌아가기
			//return restCRLService.getRevokedList();
			return true;
		}

	
	
	
	
	
	// 인증서 검증
	@GetMapping(path ="validate/{certId}", produces = "application/json")
		public Boolean validationCert(@PathVariable int certId) throws InvalidKeyException,
		CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException,
		CRLException{


			Boolean result = false; // 최종 검증 결과 result = 0 이면 "유효", result = 1이면, "폐지", 유효하지 않은 인증서로 시작
			// 최종 검증 결과 result = true 이면 "유효", result = false 이면, "폐지", 유효하지 않은 인증서로 시작

			Certificate_ cert = restCertService.getCert(certId); // 검증할 인증서 인풋
			CA certIssuer = caRepository.findOneByCaId(cert.getIssuerId());


			// (1)인증서 경로획득
			List<Certificate_> certChain = new ArrayList<>();
			CA currentCA = cert.getCa();
			certChain.add(cert); // 대상인증서
			CA issuertmp = caRepository.findOneByCaId(cert.getIssuerId()); // 대상 인증서의 발급자 임시객체
			certChain.add(issuertmp.getCertificate()); // 대상 인증서의 상위기관 소유자(subject)

		while (currentCA.getCaType() != CAType.ROOTCA) { // self sign까지 올라가기

	       	issuertmp = caRepository.findOneByCaId(issuertmp.getIssuerId()); // issuer의 issuer를 불러줘야 되는데 issuer의 자기자신을 불러주고 있어서 무한루프 도는것였음.
			currentCA = caRepository.findOneByCaId(issuertmp.getIssuerId());
			certChain.add(currentCA.getCertificate());

			if (currentCA.getCaType() == CAType.ROOTCA) {
					break;
				}
			}
			result = restCertService.validateCertNewNew(result, cert, certChain, certIssuer);

		    //if (result == 0 || result == 2) { // 폐지된 인증서 없음
			if( result == true){
				System.out.println("'유효한 인증서 입니다.'");
			} else {
				System.out.println("'유효하지 않은 인증서 입니다.'");
			}
			return result;
		}
	
	// 인증서 다운로드
	@GetMapping(path = "download/{certId}", produces = "application/json")
	public byte[] downloadCert(@PathVariable int certId) throws FileNotFoundException, CertificateException {

		Certificate_ cert = restCertService.getCert(certId); // 인증서ID 인풋
		byte[] rawdata = cert.getRawData();
		Certificate certToDownload = restCertService.downloadCert(certId, cert, rawdata); // 인증서 다운로드
		System.out.println("rawdata " + rawdata);
		System.out.println("downlaodCert " + certToDownload);

		return rawdata;
	}

}
