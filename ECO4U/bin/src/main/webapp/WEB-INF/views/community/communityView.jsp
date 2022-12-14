<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
    <%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>

<script type="text/javascript" src="${pageContext.request.contextPath}/js/jquery-3.6.0.min.js"></script>
<script type="text/javascript" src="${pageContext.request.contextPath}/js/board.fav.js"></script>
<script type="text/javascript" src="${pageContext.request.contextPath}/js/board.reply.js"></script>
<script type="text/javascript" src="${pageContext.request.contextPath}/js/videoAdapter.js"></script>
<div class="page-main">
	<h2>${community.c_title}</h2>
	<ul class="detail-info">
	
		<li>
			${community.id}
			
			<br>
			<c:if test="${!empty community.modify_date}">
			최근 수정일 : ${community.modify_date}	
			</c:if>
			<c:if test="${empty community.modify_date}">
			작성일 : ${community.reg_date}	
			</c:if>
			조회 : ${community.c_hit}
		</li>
	</ul>
	<ul>
		<c:if test="${!empty community.c_filename}">
		<li>
			첨부파일 : <a href="file.do?c_num=${community.c_num}">${community.c_filename}</a>
		</li>
		</c:if>
	</ul>
	<hr size="1" width="100%">
	<c:if test="${fn:endsWith(community.c_filename,'.jpg') ||
	              fn:endsWith(community.c_filename,'.JPG') ||
	              fn:endsWith(community.c_filename,'.jpeg') ||
	              fn:endsWith(community.c_filename,'.JPEG') ||
	              fn:endsWith(community.c_filename,'.gif') ||
	              fn:endsWith(community.c_filename,'.GIF') ||
	              fn:endsWith(community.c_filename,'.png') ||
	              fn:endsWith(community.c_filename,'.PNG')}">
	<div class="align-center">
		<img src="imageView.do?c_num=${community.c_num}&c_category=2" style="max-width:800px;">
	</div>
	</c:if>
	<p>
		${board.content}
	</p>
	<div>
		<%-- 좋아요 --%>
		<img id="output_fav" src="${pageContext.request.contextPath}/images/community/fav01.gif" width="40">
		<span id="output_fcount"></span>
	</div>
	<hr size="1" width="100%">
	<div class="align-right">
		<c:if test="${!empty user && user.mem_num == community.mem_num}">
		<input type="button" value="수정" 
		  onclick="location.href='update.do?c_num=${community.c_num}'">
		<input type="button" value="삭제" id="delete_btn">
		<script type="text/javascript">
			let delete_btn = document.getElementById('delete_btn');
			//이벤트 연결
			delete_btn.onclick=function(){
				let choice = confirm('삭제하시겠습니까?');
				if(choice){
					location.replace('delete.do?c_num=${community.c_num}');
				}
			};
		</script>  
		</c:if>
		<input type="button" value="목록"
		       onclick="location.href='list.do'">
	</div>
	<hr size="1" width="100%">
	<!-- 댓글 UI 시작 -->
	<div id="comment_div">
		<span class="com-title">댓글 달기</span>
		<form id="com_form">
			<input type="hidden" name="c_num"
			   value="${community.c_num}" id="c_num">
			<textarea rows="3" cols="50" 
			  name="com_content" id="com_content"
			  class="com-content"
			  <c:if test="${empty user}">disabled="disabled"</c:if>
			  ><c:if test="${empty user}">로그인해야 작성할 수 있습니다.</c:if></textarea>
			<c:if test="${!empty user}">
			<div id="re_first">
				<span class="letter-count">300/300</span>
			</div>
			<div id="com_second" class="align-right">
				<input type="submit" value="전송">
			</div>
			</c:if>
		</form>
	</div>
	<!-- 댓글 목록 출력 -->
	<div id="output"></div>
	<div class="paging-button" style="display:none;">
		<input type="button" value="다음글 보기">
	</div>
	<div id="loading" style="display:none;">
		<img src="${pageContext.request.contextPath}/images/community/loading.gif" width="100" height="100">
	</div>
	<!-- 댓글 UI 끝 -->
</div>
<!-- 내용 끝 -->
