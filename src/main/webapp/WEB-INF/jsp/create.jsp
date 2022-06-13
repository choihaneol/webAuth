<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<script src="../resources/bootstrap.min.css"></script>
<link href="../resources/bootstrap.min.css" rel="stylesheet">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Certificate registration</title>
</head>
<body>
	<h1>Certificate Registration</h1>
​
	<div>
		<form action="/create" method="post">
			<!-- 주임님 수정 -->
			<small id="emailHelp" class="form-text text-muted">We'll never share your information with anyone else.</small><br>	
			
			<label for="exampleInputUsername"> User name</label><br>	
			<input type="text" name="userName" placeholder="Enter your name" value="" /><br><br>
			
			<label for="exampleInputCompany"> Company</label><br>				
			<input type="text" name="company" placeholder="Enter your company" value="" /><br><br>
			
			<label for="exampleInputEmail1"> Email address</label><br>					
			<input type="text" name="email" placeholder="Enter your email" value="" /><br><br>
			<input type="hidden" name="caid"  value="${caId}" />
			
			<!-- <br> <input type="submit" value="Submit" /><br>  --> <!-- 부트스트랩 적용 전 -->
			<br> <button type="submit" class="btn btn-primary">Submit</button><!-- 부트스트랩 적용 후 -->
			
			<button type="button" class="btn btn-primary"> <a href="/ca_list"> List </button>
		
		</form>
	</div>
​
</body>
</html>
​