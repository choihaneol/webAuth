package com.example.pkiDemo.controller;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.pkiDemo.entity.CA;
import com.example.pkiDemo.entity.CAType;
import com.example.pkiDemo.entity.CRL_;
import com.example.pkiDemo.entity.Certificate_;
import com.example.pkiDemo.entity.RevokedCertificate;
import com.example.pkiDemo.repository.CARepository;
import com.example.pkiDemo.repository.CRLRepository;
import com.example.pkiDemo.service.RestCRLService;

@RestController
@RequestMapping("/CRL")
public class RestCRLController {

	@Autowired
	private CARepository caRepository;

	@Autowired
	private CRLRepository crlRepository;

	@Autowired
	private RestCRLService restCRLService;

	
	
	// CRL 조회
	@GetMapping(path = "/{caId}", produces = "application/json")
	public List<RevokedCertificate> getCRL(@PathVariable int caId) throws CertificateException, CRLException {

		CA ca = caRepository.findOneByCaId(caId);
		int crlId = ca.getCrlId();
		CRL_ crl_ = crlRepository.findOneByCrlId(crlId);

		if (crl_ == null) { // CRL 없을시 목록으로
			System.out.println("해당기관에는 폐지된 인증서가 존재 하지 않습니다. ");
		} else {
			System.out.println("해당기관에는 폐지된 인증서가 존재 합니다. ");
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			CRL crl = cf.generateCRL(new ByteArrayInputStream(crl_.getRawData()));
			return crl_.getRevokedCerts();
		}

		return null;
	}
	
	
	

	// CRL 검증
	@GetMapping(path = "validate/{caId}", produces = "application/json")
	public boolean validationCRL(@PathVariable int caId) throws InvalidKeyException, CertificateException, CRLException,
			NoSuchAlgorithmException, NoSuchProviderException, SignatureException {

		boolean result = false;

		CA ca = caRepository.findOneByCaId(caId);
		Certificate_ cert = ca.getCertificate();

		if (cert.getCa().getCrlId() != 0) { // CRL존재 할 경우에만 CRL검증 거친다. 하지만 실제 폐지리스트는(DB에서는) CRL발급자는 대상인증기관이 아닌 상위기관의
											// CRL에 저장되어 있다.
			// crlChain 획득
			CA currentCA = cert.getCa();
			List<Certificate_> certChain = new ArrayList<>();
			certChain.add(cert);
			CA issuertmp = caRepository.findOneByCaId(cert.getIssuerId()); // 임시객체.ICA인증서일경우 조건문 통과해버림.
			while (currentCA.getCaType() != CAType.ROOTCA) { // self sign까지 올라가기
				issuertmp = caRepository.findOneByCaId(issuertmp.getIssuerId()); // issuer의 issuer를 불러줘야 되는데 issuer의
																					// 자기자신을 불러주고 있어서 무한루프 도는것였음.
				currentCA = caRepository.findOneByCaId(issuertmp.getIssuerId());

				certChain.add(currentCA.getCertificate());

				if (currentCA.getCaType() == CAType.ROOTCA) {
					break;
				}
			}

			for (int i = 0; i < certChain.size(); i++) {
				System.out.println("Certificate " + certChain.get(i).getCertId());
			}

			// 인증서체인 순서 루트부터 정렬
			Collections.reverse(certChain);

			List<Certificate_> crlChain = new ArrayList<>();
			crlChain = certChain;

			// crl 자체 검증
			for (int i = 0; i < certChain.size(); i++) {
				result = restCRLService.validateCRLNewNew(result, cert, certChain, certChain.get(i));
			}
		} else { // CRL 존재X
			result = false; // result =2 였음
		}

		if (result == true) {
			System.out.println("인증서폐지목록이 검증 되었습니다.");
		} else {
			System.out.println("검증되지 않은 인증서 폐지목록입니다.");
		}

		return result;
	}

	
	
	
	// CRL 다운로드
	@GetMapping(path = "download/{crlId}", produces = "application/json")
	public byte[] downloadCRL(@PathVariable int crlId)
			throws FileNotFoundException, CRLException, CertificateException {
		CRL_ crl = crlRepository.findOneByCrlId(crlId);
		byte[] rawdata = crl.getRawData();
		CRL crlToDownload = restCRLService.downloadCRL(crlId, crl, rawdata);

		return rawdata;
	}

}
