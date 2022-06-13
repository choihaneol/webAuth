<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<script src="../resources/bootstrap.min.css"></script>
<link href="../resources/bootstrap.min.css" rel="stylesheet">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=EUC-KR">
<title>Certificate Information - Spring Boot Web Application Example</title>
</head>
<body>
<div id = "root">
<header>
	<h1 align="center">Certificate Information</h1>
	<hr/>
<nav>
<h4> Certificate management </h4>
</nav>
<hr/>
<section id="container">
<form role="form" method="post" autocompete="off">
 <p>
   <label for="certId">Certificate ID  </label><input type="text" size="3" id="certId" name="certId" value="${read.certId}" readonly="readonly" /> <br>
   <label for="certId">Serial Number  </label><input type="text" id="serialNumber" name="v" value="${read.serialNumber}" readonly="readonly" /> <br>
   <label for="certId">Expired Date (Start)  </label><input type="text" id="expiredDateStart" name="expiredDateStart" value="${read.expiredDateStart}" readonly="readonly" /> <br>
   <label for="certId">Expired Date (End)  </label><input type="text" id="expiredDateEnd" name="expiredDateEnd" value="${read.expiredDateEnd}" readonly="readonly" /> <br>
   <label for="certId">Subject Name  </label><input type="text" size="50" id="subjectName" name="subjectName" value="${read.subjectName}" readonly="readonly" /> <br>
   <label for="certId">Public Key  </label><input type="text" size="50" id="publicKey" name="publicKey" value="${read.publicKey}" readonly="readonly" /> <br>
  <!--  <label for="certId">Private Key  </label><input type="text" size="50" id="privateKey" name="privateKey" value="${read.privateKey}" readonly="readonly" /> <br>  -->
   <label for="certId">CA Digital Signiture  </label><input type="text" size="50"  id="caDigitalSigniture" name="caDigitalSigniture" value="${read.signature}" readonly="readonly" /> <br>  
  </p>
</form>
​
​
		<button type="button" class="btn btn-primary">
			<a href="/validation?certId=${read.certId}">Validation</button></a>	
		<button type="button" class="btn btn-primary">
			<a href="/download?certId=${read.certId}">Download</button></a>
		<button type="button" class="btn btn-primary">
			<a href="/revoke?certId=${read.certId}"> Revoke </button></a>
		<br>
		<br>
		<button type="button" class="btn btn-primary"><a href="/ca_list"> List </button></a>
		</section>
<hr />
<footer>
<p> Fescaro </p>
</footer>
​
</header>
</div>
​
</body>
</html>
​