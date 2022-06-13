package com.example.pkiDemo.controller;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import com.example.pkiDemo.entity.CA;
import com.example.pkiDemo.entity.CAType;
import com.example.pkiDemo.entity.CRL_;
import com.example.pkiDemo.entity.Certificate_;
import com.example.pkiDemo.repository.CARepository;
import com.example.pkiDemo.repository.CRLRepository;
import com.example.pkiDemo.service.CRLService;
import com.example.pkiDemo.service.CertService;

@Controller
@RequestMapping("/")
public class CRLController {



	@Autowired // 주임님수정
	private CertService certService;
	
	@Autowired
	private CRLService crlService;
	
	@Autowired
	private CARepository caRepository;

	@Autowired
	private CRLRepository crlRepository;
	
	@GetMapping("readCRL") // 주임님 수정
	public String getCRL(HttpServletRequest request, HttpServletResponse response, int caId, CAType caType, Model model)
			throws IOException, CRLException, CertificateException {
		
		response.setContentType("text/html; charset=UTF-8");
		PrintWriter out = response.getWriter();

		// 기관선택
		String catype = request.getParameter("CAType"); // CAtype 모델에 담아서 caLIst()로 받아와 -> createPage()로 보내 -> register()로 보내

		model.addAttribute("caId", caId);
		model.addAttribute("CAType", caType);

		// 여기서 caId 가공gotj crlId 찾아
		CA ca = caRepository.findOneByCaId(caId);
		int crlId = ca.getCrlId();
		CRL_ crl = crlRepository.findOneByCrlId(crlId);
		// crlId -> URL로 뿌려줘
		
		
		if ( crl ==null){ // CRL 없을시 목록으로 되돌아가기
 			out.println("<script>alert('해당기관에는 폐지된 인증서가 존재 하지 않습니다. '); history.go(-1);</script>"); // 2페이지 뒤로가기
			out.flush();
		}
		
		crl.setSignature(Hex.toHexString(crl.getCrlIssuerDigitalSigniture())); // 브라우저 서명 에러

		model.addAttribute("crl", crl);
		model.addAttribute("crlId", crlId);

		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		CRL crll = cf.generateCRL(new ByteArrayInputStream(crl.getRawData()));
		// X509CRLHolder holder = new X509CRLHolder(crl.getRawData());


		// 선택기관 CRL만 뽑는다 -> 폐지인증서 하나씩만 나오는 에러!!!!!
		List<CRL_> crlList = crlService.getCrlList();


		model.addAttribute("crlList", crlList); // 여기서 CRL.jsp 의 list로 뿌려줘
		
		return "readCRL";
			
	}
	


	
	@RequestMapping(value = "/CRLvalidation", method = RequestMethod.GET)
	public void validationCRL(@RequestParam("caId") int caId, HttpServletRequest request, HttpServletResponse response,
			Model model) throws InvalidKeyException, IllegalStateException, NoSuchProviderException,
			NoSuchAlgorithmException, SignatureException, OperatorCreationException, CertificateException,
			InvalidKeySpecException, CRLException, IOException {


		int result = 1; // 최종 검증 결과 result = 0 이면 "유효", result = 1이면, "폐지", 유효하지 않은 인증서로 시작  
		CA ca = caRepository.findOneByCaId(caId);
		Certificate_ cert = ca.getCertificate();
		CRL_ crl = crlRepository.findOneByCrlId(cert.getCa().getCrlId());
		
			
		
		if (cert.getCa().getCrlId() != 0 ) { // CRL존재 할 경우에만 CRL검증 거친다. 하지만 실제 폐지리스트는(DB에서는) CRL발급자는 대상인증기관이 아닌 상위기관의 CRL에 저장되어 있다.
	
			//crlChain 획득
			CA currentCA = cert.getCa();
			List<Certificate_> certChain = new ArrayList<>();
			certChain.add(cert);
			CA issuertmp = caRepository.findOneByCaId(cert.getIssuerId()); // 임시객체.ICA인증서일경우 조건문 통과해버림.
			while (currentCA.getCaType() != CAType.ROOTCA) { // self sign까지 올라가기
 				issuertmp = caRepository.findOneByCaId(issuertmp.getIssuerId()); // issuer의 issuer를 불러줘야 되는데 issuer의 자기자신을 불러주고 있어서 무한루프 도는것였음.
				currentCA = caRepository.findOneByCaId(issuertmp.getIssuerId());
			
				certChain.add(currentCA.getCertificate());
				
				if (currentCA.getCaType() == CAType.ROOTCA) {
					break;
				}
			}
			
			
		 
			
			// 인증서체인 순서 루트부터 정렬
			Collections.reverse(certChain);
			
			List<Certificate_> crlChain = new ArrayList<>();
			crlChain = certChain;


			//crl 자체 검증
			for (int i = 0; i < certChain.size(); i++) {
			//result = crlService.validateCRLNew(result, cert, certChain, certChain.get(i), crl);
			result = crlService.validateCRLNewNew(result, cert, certChain, certChain.get(i));
			//result:검증결과, cert:대상인증서, certChain:인증서경로, certChain.get(i):경로에서 현재시점에서 검증중인 인증서, crl:검증대상기관의 CRL
			}
		}
		else{ //CRL 존재X
			result =2;
		}
		
			
		
		//알림창
		response.setContentType("text/html; charset=UTF-8");
		PrintWriter out = response.getWriter();
		if (result == 0) {
 			out.println("<script>alert('인증서폐지목록이 검증 되었습니다.'); history.go(-2);</script>"); // 2페이지 뒤로가기
			out.flush();

		} else if (result ==1){
 			out.println("<script>alert('검증되지 않은 인증서 폐지목록입니다.'); history.go(-2);</script>"); // 2페이지 뒤로가기
			out.flush();


		} else if (result ==2){
 		out.println("<script>alert('해당 기관에 폐지된 인증서가 존재 하지 않습니다. '); history.go(-2);</script>"); // 2페이지 뒤로가기
		out.flush();
	    }
	}
		
	
	
	@RequestMapping(value = "CRLdownload", method = RequestMethod.GET)
	public String downloadCRL(@RequestParam("crlId") int crlId, HttpServletRequest request, Model model)
			throws InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException,
			SignatureException, OperatorCreationException, CertificateException, InvalidKeySpecException, CRLException,
			FileNotFoundException {
		//caId = Integer.parseInt(request.getParameter("caId"));
		crlId = Integer.parseInt(request.getParameter("crlId"));

		CRL_ crl = crlRepository.findOneByCrlId(crlId);
		byte[] rawdata = crl.getRawData();
		
		crlService.downloadCRL(crlId, crl, rawdata);
		
	
		return "redirect:/CRLdownloadcomplete"; //다운로드 완료 후 목록으로 돌아가기
	}
	
	
	
	
	
	// 알림창
	@RequestMapping("/CRLdownloadcomplete")
	public String downloadcomplete(HttpServletRequest request, HttpServletResponse response) throws Exception {
		// String url="redirect:/ca_list";// "/admin/main/dashboard";
		
		
		response.setContentType("text/html; charset=UTF-8");
		PrintWriter out = response.getWriter();
		out.println("<script>alert('다운로드가 완료되었습니다.'); history.go(-2);</script>"); // 2페이지 뒤로가기
		out.flush();


		return "redirect:/ca_list";
	}
	
	

}
