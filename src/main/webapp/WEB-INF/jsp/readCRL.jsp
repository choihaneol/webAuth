
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<script src="../resources/bootstrap.min.css"></script>
<link href="../resources/bootstrap.min.css" rel="stylesheet">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=EUC-KR">
<title>Certificate Revocation List - Spring Boot Web Application Example</title>
</head>
<body>
​
​
​
	<h1 align="center">Certificate Revocation List</h1>
	<br />
	<form action="/readCRL" method="post" id="form">
		<table border="1" cellpadding="10">
			<tr class="table-primary">
				<th scope="row">CRL ID</th>
				<th scope="row">Issuer</th>
				<th scope="row">Update date(Last)</th>
				<th scope="row">Update date(Next)</th>
				<th scope="row">Certificate serial number</th>
				<th scope="row">Revocation Date</th>
				<th scope="row">Revocation Reason</th>
				<th scope="row">Issuer Digital Signiture</th>
			</tr>
			
			<c:forEach var="revoked" items="${crl.revokedCerts}"> <!-- crlList가 아니라 revoked certificate 기준에서 반복되야 되기 때문에  items에 "crl.revokedCerts" 가 들어감 -->
				<tr>
					<!-- <td><a href="/read?certId=${list.caId}">${list.caId}</a></td> -->
					<!-- row -->
					<td>${crl.crlId}</td>  <!-- revokedCertificateId (RevokedCertificate) -->
					<td>${crl.crlIssuerName}</td>  <!-- revokedCertificateId (CRL_)-->
					<td>${crl.updateDateLast}</td>  <!-- updateDateLast (CRL_) -->
					<td>${crl.updateDateNext}</td>  <!-- updateDateNext (CRL_) -->
					<td>${revoked.certificateSerialNumber}</td>  <!-- CertificateSerialNumber (RevokedCertificate) -->
					<td>${revoked.revocationDate}</td>  <!-- revocationDate (RevokedCertificate) -->
					<td>${revoked.revokedReason}</td>  <!-- revokedReason (RevokedCertificate) -->
					<td>${crl.signature}</td>  <!-- crlIssuerDigitalSigniture (CRL_) -->					
				</tr>
		 </c:forEach>
		</table>
	</form>
​
	<br>
	<p>
​
		<button type="button" class="btn btn-primary">
			<a href="/CRLvalidation?caId=${caId}">Validation</button>
		<button type="button" class="btn btn-primary">
			<a href="/CRLdownload?crlId=${crlId}">Download</button>
		<!-- <button type="button" class="btn btn-primary btn-lg"><a href="/revoke">  Revoke </button></a><br><br>  -->
		<!-- 해당기관의 caId 찾아서 CRL있는지 확인 -->
		<button type="button" class="btn btn-primary">
			<a href="/ca_list"> List </button>
​
​
​
​
		</section>
	<hr />
	<footer>
	<p>Fescaro</p>
	</footer>
	</header>
	</div>
</body>
</html>