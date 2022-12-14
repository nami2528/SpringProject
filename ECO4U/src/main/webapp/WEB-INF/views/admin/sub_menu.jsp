<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!-- css 삽입 -->
<link rel="stylesheet" href="${pageContext.request.contextPath}/css/admin.css">
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans+KR&display=swap" rel="stylesheet">

<!-- 서브메뉴 시작 -->
<div class="sub-menu">
	<div class="sub-detail">
		<div class="image-user">
			<img src="${pageContext.request.contextPath}/images/faq/management3.png">
			<p>${param.mem_name}<p>
		</div>
		
		<div class="submenu-title">
			<div class="subtitle-box">
				<h2>회원관리</h2>
				<p><a href="${pageContext.request.contextPath}/admin/admin_list.do" style="color: darkgray;">- 전체회원</a></p>
				<p><a href="${pageContext.request.contextPath}/admin/delete_list.do" style="color: darkgray;">- 탈퇴/정지회원</a></p>
			</div>
			
			<div class="subtitle-box">
				<h2>상품관리</h2>
				<p><a href="${pageContext.request.contextPath}/product/admin_plist.do" style="color: darkgray;">- 전체상품</a></p>			
				<p><a href="${pageContext.request.contextPath}/product/admin_write.do" style="color: darkgray;">- 상품등록</a></p>
			</div>
			
			<div class="subtitle-box">
				<h2><a href="${pageContext.request.contextPath}/faq/qnamanagementlist.do">문의관리</a></h2>
			</div>
			
			<div class="subtitle-box">
				<h2><a href="${pageContext.request.contextPath}/order/admin_orderList.do">주문관리</a></h2>
			</div>
		</div>
	</div>
</div>
<!-- 서브메뉴 끝 -->