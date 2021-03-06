package com.example.pkiDemo.controller;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import com.example.pkiDemo.entity.CA;
import com.example.pkiDemo.entity.CAType;
import com.example.pkiDemo.entity.Certificate_;
import com.example.pkiDemo.repository.CARepository;
import com.example.pkiDemo.repository.CertRepository;
import com.example.pkiDemo.service.CRLService;
import com.example.pkiDemo.service.CertService;

@Controller
@RequestMapping("/")
public class CertController {

	@Autowired
	private CertService certService;

	@Autowired
	private CRLService crlService;

	@Autowired
	private CARepository caRepository;

	@Autowired
	private CertRepository crtRepository;

	@GetMapping("ca_list")
	public String getList(HttpServletRequest request, Model model)
			throws InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException,
			SignatureException, OperatorCreationException, CertificateException {

		// checkRootCA(); // RootCA 여부 확인
		List<CA> caList = certService.getList();

		// 기관선택
		String catype = request.getParameter("caType");

		model.addAttribute("list", caList);
		model.addAttribute("/createPage", catype);
		System.out.println(catype);

		return "list";
	}

	public void checkRootCA() throws InvalidKeyException, IllegalStateException, NoSuchProviderException,
			NoSuchAlgorithmException, SignatureException, OperatorCreationException, CertificateException {
		CA ca = caRepository.findOneByCaType(CAType.ROOTCA);
		if (ca == null) {

			// RootCA생성
			java.security.cert.Certificate cert = certService.generateSelfSignedX509RootCertificate();
		} else {
			System.out.println(ca);
		}
		return;
	}

	@RequestMapping(value = "read", method = RequestMethod.GET)
	public void getCert(@RequestParam("certId") int certId, Model model) throws Exception {

		Certificate_ crt = certService.getCert(certId);
		crt.setSignature(Hex.toHexString(crt.getCaDigitalSigniture()));
		model.addAttribute("read", crt);
	}

	// @RequestMapping("createPage")
	@GetMapping("createPage") // 주임님 수정
	public String createPage(HttpServletRequest request, int caId, CAType caType, Model model) {

		// 기관선택
		// String catype = request.getParameter("CAType");
		model.addAttribute("caId", caId);
		model.addAttribute("CAType", caType);

		return "create";
	}
	// 인증서발급 버튼 클릭 -> /createPage로 페이지이동-> /create(jsp) 콜 -> 필드값 /create(컨트롤러)에 post
	// -> /create(컨트롤러) 타고 /list(jsp) 보여줌

	// 사용자 인풋정보 form 사용하기. 인증서 발급후 CA 목록으로 돌아감
	@PostMapping(value = "create")
	public String register(HttpServletRequest request, Model model)
			throws InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException,
			SignatureException, OperatorCreationException, CertificateException, InvalidKeySpecException {

		// 필드값 인풋
		String userName = request.getParameter("userName");
		String company = request.getParameter("company");
		String email = request.getParameter("email");

		int caId = Integer.parseInt(request.getParameter("caid")); // 발급자 id 로 조회해서 발급자 정보기준으로 생성 해야함.

		// caId 찾아라 (발급 기관 id(issuerId)로 해당 기관의 CAType을 조회 -> RootCA면 ICA로 변경, ICA면
		// End-entity로 변경)
		CA issuer = caRepository.findOneByCaId(caId);

		if (issuer.getCaType() == CAType.ROOTCA || issuer.getCaType() == CAType.ICA) {
			certService.generateCert(userName, company, email, issuer.getCaType(), issuer);
		} else if (issuer.getCaType() == CAType.ENDENTITY) {
			return "redirect:/noendentity"; // 알림창
		}

		// 인증서 생성 후 다시 기관목록으로 되돌아가기
		List<CA> caList = certService.getList();
		model.addAttribute("list", caList);
		return "redirect:/ca_list";
	}

	@RequestMapping("/noendentity")
	public String noendentity(HttpServletRequest request, HttpServletResponse response) throws Exception {

		response.setContentType("text/html; charset=UTF-8");
		PrintWriter out = response.getWriter();
		out.println("<script>alert('인증서 발급이 불가합니다. 발급기관 정보를 확인해주세요.'); history.go(-2);</script>"); // 2페이지 뒤로가기
		out.flush();

		return "redirect:/ca_list";
	}

	@RequestMapping(value = "revoke", method = RequestMethod.GET)
	public String revoke(@RequestParam("certId") int certId, HttpServletRequest request, Model model,
			HttpServletResponse response) throws InvalidKeyException, IllegalStateException, NoSuchProviderException,
			NoSuchAlgorithmException, SignatureException, OperatorCreationException, CertificateException,
			InvalidKeySpecException, CRLException, IOException {

		// certId로 caId 조회 -> caId로 crlId 조회 -> Null이면 생성하고 Null아니면 CRL에 폐기인증서 추가 -> 모달창
		Certificate_ cert = crtRepository.findOneByCertId(certId);

		CA ca = cert.getCa();

		int issuerId = ca.getIssuerId();
		String issuerName = cert.getIssuerName();

		int crlId = ca.getCrlId();
		CAType caType = ca.getCaType();

		CA issuerCA = caRepository.findOneByCaId(issuerId);
		int issuerCRLID = issuerCA.getCrlId();

		if (caType == CAType.ROOTCA) { // RootCA면 삭제 불가
			return "redirect:/norootcadelete";

		} else {

			if (issuerCRLID == 0) { // CRL 없으면 생성 -> 폐지인증서 추가
				crlService.generateICACRL(certId, issuerId, issuerName, caType);
			} else { // CRL 존재 -> 폐지인증서만 추가
				// crlService.revokeCertificate(certId, issuerId, issuerName, caType);
				crlService.revokeCertificate(certId, issuerId, issuerName, caType, response);
			}

		}

		// 인증서 폐기 후 다시 기관목록으로 되돌아가기
		List<CA> caList = certService.getList();
		model.addAttribute("list", caList);
		// return "list";
		return "redirect:/deletecomplete";
	}

	@RequestMapping("/norootcadelete")
	public String norootcadelete(HttpServletRequest request, HttpServletResponse response) throws Exception {
		// String url="redirect:/ca_list";// "/admin/main/dashboard";

		response.setContentType("text/html; charset=UTF-8");
		PrintWriter out = response.getWriter();
		out.println("<script>alert('해당 인증서는 폐기 불가합니다.'); history.go(-2);</script>"); // 2페이지 뒤로가기
		out.flush();

		return "redirect:/ca_list";
	}

	@RequestMapping("/deletecomplete")
	public String deletecomplete(HttpServletRequest request, HttpServletResponse response, Model model)
			throws Exception {

		response.setContentType("text/html; charset=UTF-8");
		PrintWriter out = response.getWriter();
		out.println("<script>alert('인증서가 폐기 되었습니다.'); history.go(-2);</script>"); // 2페이지 뒤로가기
		out.flush();

		// 인증서 생성 후 다시 기관목록으로 되돌아가기
		List<CA> caList = certService.getList();
		model.addAttribute("list", caList);
		// return "list";
		return "redirect:/ca_list";
	}

	@RequestMapping(value = "validation", method = RequestMethod.GET)
	public String validationCert(@RequestParam("certId") int certId, HttpServletRequest request,
			HttpServletResponse response, Model model) throws InvalidKeyException, IllegalStateException,
			NoSuchProviderException, NoSuchAlgorithmException, SignatureException, OperatorCreationException,
			CertificateException, InvalidKeySpecException, CRLException, IOException {

		int result = 1; // 최종 검증 결과 result = 0 이면 "유효", result = 1이면, "폐지", 유효하지 않은 인증서로 시작

		Certificate_ cert = certService.getCert(certId); // 검증할 인증서 인풋
		CA certIssuer = caRepository.findOneByCaId(cert.getIssuerId());

		// (1)인증서 경로획득
		List<Certificate_> certChain = new ArrayList<>();
		CA currentCA = cert.getCa();

		certChain.add(cert); // 대상인증서

		CA issuertmp = caRepository.findOneByCaId(cert.getIssuerId()); // 대상 인증서의 발급자 임시객체
		certChain.add(issuertmp.getCertificate()); // 대상 인증서의 상위기관 소유자(subject)

		while (currentCA.getCaType() != CAType.ROOTCA) { // self sign까지 올라가기

			issuertmp = caRepository.findOneByCaId(issuertmp.getIssuerId()); // issuer의 issuer를 불러줘야 되는데 issuer의 자기자신을
																				// 불러주고 있어서 무한루프 도는것였음.
			currentCA = caRepository.findOneByCaId(issuertmp.getIssuerId());
			certChain.add(currentCA.getCertificate());

			if (currentCA.getCaType() == CAType.ROOTCA) {
				break;
			}
		}

		// result:검증결과, cert:대상인증서, certChain:인증서경로, certIssuer:인증서발급자
		result = certService.validateCertNewNew(result, cert, certChain, certIssuer);

		response.setContentType("text/html; charset=UTF-8");
		PrintWriter out = response.getWriter();

		if (result == 0 || result == 2) { // 폐지된 인증서 없음
			out.println("<script>alert('유효한 인증서 입니다.'); history.go(-2);</script>"); // 2페이지 뒤로가기
			out.flush();
		} else {
			out.println("<script>alert('유효하지 않은 인증서 입니다.'); history.go(-2);</script>"); // 2페이지 뒤로가기
			out.flush();

		}

		// 인증서 생성 후 다시 기관목록으로 되돌아가기
		List<CA> caList = certService.getList();
		model.addAttribute("list", caList);
		return "redirect:/ca_list";
	}

	@RequestMapping(value = "download", method = RequestMethod.GET)
	public String downloadCert(@RequestParam("certId") int certId, HttpServletRequest request, Model model)
			throws InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException,
			SignatureException, OperatorCreationException, CertificateException, InvalidKeySpecException, CRLException,
			FileNotFoundException {

		Certificate_ cert = certService.getCert(certId);

		byte[] rawdata = cert.getRawData();

		certService.downloadCert(certId, cert, rawdata);

		// 인증서 생성 후 다시 기관목록으로 되돌아가기
		List<CA> caList = certService.getList();
		model.addAttribute("list", caList);

		return "redirect:/downloadcomplete";
	}

	// 알림창
	@RequestMapping("/downloadcomplete")
	public String downloadcomplete(HttpServletRequest request, HttpServletResponse response) throws Exception {
		// String url="redirect:/ca_list";// "/admin/main/dashboard";

		response.setContentType("text/html; charset=UTF-8");
		PrintWriter out = response.getWriter();
		out.println("<script>alert('다운로드가 완료되었습니다.'); history.go(-2);</script>"); // 2페이지 뒤로가기
		out.flush();

		return "redirect:/ca_list";
	}

}
