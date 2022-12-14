<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!-- 내용 시작 -->
<!-- 자바스크립트 삽입 -->
<script type="text/javascript" src="${pageContext.request.contextPath}/js/jquery-3.6.0.min.js"></script>
<script type="text/javascript" src="${pageContext.request.contextPath}/js/member.js"></script>

<!-- css 삽입 -->
<link rel="stylesheet" href="${pageContext.request.contextPath}/css/admin.css">

<!-- 본문 내용 -->
<jsp:include page="/WEB-INF/views/admin/sub_menu.jsp">
	<jsp:param name="mem_name" value="${admin.mem_name}"/>
</jsp:include>

<div class="main-content">
	<div class="sub-title">
		<span class="sub_1">전체회원</span>
		<span class="sub_2">관리 메뉴에서 <span style="font-weight:bold; color:red">회원등급 수정</span>이 가능합니다.</span>
	</div>
	
	
	<div class="search">
		<form action="admin_list.do" id="search_form" method="get">
			<select name="keyfield">
				<option value="1" <c:if test="${param.keyfield == 1}">selected</c:if>>ID</option>
				<option value="2" <c:if test="${param.keyfield == 2}">selected</c:if>>이름</option>
				<option value="3" <c:if test="${param.keyfield == 3}">selected</c:if>>이메일</option>
				<option value="4" <c:if test="${param.keyfield == 4}">selected</c:if>>전체</option>
			</select>
			<input type="search" name="keyword" id="keyword" value="${param.keyword}">
			<input type="submit" value="찾기"> <input type="button" value="목록" onclick="location.href='admin_list.do'">
		</form>
	</div>
	
	<div class="content-list">
		<!-- 회원 수가 0명일 경우 -->
		<c:if test="${count == 0}">
			<div class="search-result">표시할 회원 정보가 없습니다.</div>
		</c:if>
		
		<!-- 회원 수가 1명 이상일 경우 -->
		<c:if test="${count > 0}">
		<table>
			<tr>
				<th>ID</th>
				<th>이름</th>
				<th>이메일</th>
				<th>전화번호</th>
				<th>가입일</th>
				<th>등급</th>
			</tr>

			<c:forEach var="member" items="${list}">
				<tr <c:if test="${member.auth!=0}">onclick="location.href='admin_detail.do?mem_num=${member.mem_num}'"</c:if>>
					<td><c:if test="${member.auth==0}"><span style="color:#BDBDBD;">${member.id}</span></c:if> 
					<c:if test="${member.auth > 0}">
							${member.id}
					</c:if></td>
					<td>${member.mem_name}</td>
					<td>${member.mem_email}</td>
					<td>${member.mem_cell}</td>
					<td>${member.reg_date}</td>
					<td>
						<c:if test="${member.auth==0}">탈퇴</c:if>
						<c:if test="${member.auth==1}">일반</c:if> 
						<c:if test="${member.auth==2}">관리자</c:if>
						<c:if test="${member.auth==3}">정지</c:if>
					</td>
				</tr>
			</c:forEach>
		</table>
		<div class="page-num">< ${page} ></div>
		</c:if>
	</div>
</div>
<!-- 내용 끝 -->