<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<style>
#id{
	font-size: 15px;
	margin-top: 20px;
}
#mem_cell{
	font-size: 15px;
}
.submit-btn{
	color:white;
	font-size: 25px;
	background-color: gray;
	margin-top: 30px;
	margin-bottom: 30px;
	padding: 12px;
	border: none;
	border-radius: 5px;
	width: 90%;
	font-weight: bold;
	cursor:pointer;
}
</style>     
<!-- 내용 시작 -->
<div class="page-main">
	<div class="align-center" style="margin-top: 60px; margin-bottom: 30px;">
		<h1>비밀번호 찾기</h1>
	</div>
	<form:form id="findpasswd_form" action="doSend.do" modelAttribute="memberVO" style="border:1px solid white; border-radius:10px; height:450px; background-color:white;">
		<form:errors element="div" cssClass="error-color"/>
		<ul>
			<li>
				<label for="id" id="id">아이디</label><br>
			</li>
		</ul>
		<ul>
			<li>
				<form:input path="id" placeholder="아이디를 입력해주세요" autocomplete="off" style="width:90%; height:30px; border-radius:5px; border:1px solid gray;"/>
				<form:errors path="id" cssClass="error-color"/>
			</li>
		</ul>
		<ul>
			<li>
				<label for="mem_cell" id="mem_cell">전화번호</label><br>
			</li>
		</ul>
		<ul>
			<li>
				<form:input path="mem_cell" placeholder="전화번호를 입력해주세요" style="width:90%; height:30px; border-radius:5px; border:1px solid gray;"/>
				<form:errors path="mem_cell" cssClass="error-color"/>
			</li>
		</ul>  
		<div class="align-center" style="margin-top: 10px;">
			<input type="submit" value="이메일전송" class="submit-btn">
		</div>
		<div class="align-center" style="font-size:15px; font-color:gray; margin-top: 20px">
		가입하신 이메일 주소를 입력해주시면<br>
		새로운 비밀번호를 보내드립니다.<br>
		로그인 후 새로운 비밀번호를 변경해주세요.
		</div>	                  
	</form:form>
</div>
<!-- 내용 끝 -->