<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
  "http://www.w3.org/TR/html4/loose.dtd">
  
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Certificate List - Spring Boot Web Application Example</title>
<script src="../resources/bootstrap.min.css"></script>
<link href="../resources/bootstrap.min.css" rel="stylesheet">
<script type="text/javascript">
	function getCaType() {
		var radio = document.getElementsByName("caType");
		//var radio = form.elements["caType"];
		//alert(radio);
		//alert(radio.length);
		for (var i = 0, len = radio.length; i < len; i++) {
			//alert(radio[i].value);
			if (radio[i].checked) {
				location.href="/createPage?caId="+radio[i].value;
			}
		}
	}
</script>

<script type="text/javascript">
	function getCaId() {
		var radio = document.getElementsByName("caId");
		//var radio = form.elements["caType"];
		//alert(radio);
		//alert(radio.length);
		for (var i = 0, len = radio.length; i < len; i++) {
			//alert(radio[i].value);
			if (radio[i].checked) {
				location.href="/readCRL?caId="+radio[i].value;
			}
		}
	}
</script>
<body>
<h1>Certificate(CA) List</h1>
	<form action="/createPage" method="post" id="form">
		<table border="1" cellpadding="10" >
	 <thead>
			<tr class="table-primary">
				<th scope="row"> CA ID</th>
				<th scope="row"> CERT ID</th>
				<th scope="row"> Expired date</th>
				<th scope="row"> Certificate type</th>
			    <th scope="row"> User name</th>
			    </tr>
			    
	<c:forEach var="list" items="${list}">
				<tr>
					<!-- <td><a href="/read?certId=${list.caId}">${list.caId}</a></td> -->
				    <td><input type="radio" name="caId" value=${list.caId } /> ${list.caId}</td>
					<td><a href="/read?certId=${list.certificate.certId}">${list.certificate.certId}</a></td>
					<td>${list.certificate.expiredDateEnd}</td>
					<div>
						<td><input type="radio" name="caType" value=${list.caId } /> ${list.caType}</td>
​
					</div>
					<td>${list.certificate.userName}</td>
​
				</tr>
				
				
			</c:forEach>
		</table>
	</form>
​
	<br>
	<p>
		
 <small id="InformationHelp" class="form-text text-muted">  Click on the "certificate ID" if you want to see the details of the certificate.</small><br>	
	
	
		<!-- <button onclick="getCaType();">Registration</button>  --><!-- 주임님수정<!--  --부트스트랩 적용 전>-->  
   	<button type="button" class="btn btn-primary" onclick="getCaType();">Registration</button>
	
	<!-- <button type="button" onclick="location.href='read.jsp'" >Confirm</button>  -->
	
		<!-- <button  onclick="getCaId();">CRL</button>  --> <!-- 부트스트랩 적용 전 -->
		<button type="button" class="btn btn-primary" onclick="getCaId();">CRL</button>
		
		<!-- <button type="button" class="btn btn-primary ">CRL Validation</button>  -->
		<!-- <button type="button" class="btn btn-primary btn-lg">CRL Download</button>  -->
		<!-- <button type="button" class="btn btn-primary btn-lg">Confirm</button> -->
       <!-- <button type="button" class="btn btn-primary ">Revocation</button>-->
          <!--  <button type="button" class="btn btn-primary "> <a href="/revoke?certId=${read.certId}"> Revokation
		</button>  -->
	</p>
	

<hr />
	<footer>
	<p>Fescaro</p>
	</footer>
</body>
</head>
</html>
​
<!--
※ reference
http://jsfiddle.net/jscodedev/ukqqvL9h/1/  - 선택된 테이블 행의 정보 가지고 오기
https://bootswatch.com/flatly/ - 부트스트랩 출처
-->