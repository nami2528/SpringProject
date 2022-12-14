<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<script type="text/javascript" src="${pageContext.request.contextPath}/js/jquery-3.6.0.min.js"></script>
<script type="text/javascript" src="${pageContext.request.contextPath}/js/community.js"></script>

<div class="page-main">

	<div class="align-center">
		<h2 onclick="location.href='list.do'">Community</h2>
	</div>
	
	
				<a href="./community?c_category=1">TIP</a>
				<a href="./community?c_category=2" >함께해요</a>
				<a href="./community?c_category=3">친환경 소식</a>
			
			<div class="align-right">
				<select name="keyfield" id="keyfield">
					<option value="1" <c:if test="${param.keyfield == 1}">selected</c:if>>제목</option>
					<option value="2" <c:if test="${param.keyfield == 2}">selected</c:if>>작성자 ID</option>
					<option value="3" <c:if test="${param.keyfield == 3}">selected</c:if>>내용</option>
					<option value="4" <c:if test="${param.keyfield == 4}">selected</c:if>>제목+내용</option>
				</select>
				<input type="search" name="keyword" id="keyword"
				               value="${param.keyword}">
			<input type="submit" value="찾기">
			
	
<!-- 글쓰기 버튼 -->
<c:if test="${!empty user}">
	
		<input type="button" value="글쓰기"
		          onclick="location.href='write.do'">
	
</c:if></div>
</div>
<!-- 게시글 목록 -->
<c:if test="${count == 0}">
	<div class="result-display">표시할 게시물이 없습니다.</div>	
	</c:if>
	<c:if test="${count > 0}">
	<table>
		
		<c:forEach var="community" items="${list}">
		<tr>
			<td>${community.c_num}</td>
			<td><a href="detail.do?c_num=${community.c_num}">${community.c_title}</a></td>
			<td>${community.id}	</td>
			<td>${community.reg_date}</td>
			<td>${community.c_hit}</td>
		</tr>
		</c:forEach>
	</table>
	<div class="align-center">${page}</div>
	</c:if>	
	
	
</div>