<%@ page language="java" contentType="text/html; charset=UTF-8"
   pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<meta name="viewport" content="width=device-width, initial-scale=1">
<script type="text/javascript" src="${pageContext.request.contextPath}/js/jquery-3.6.0.min.js"></script>
<script src="http://code.jquery.com/jquery-1.8.2.min.js"></script>
<style>
	#menu01 { display:none;}
</style>
<script>
$(function(){
	$("#header_center>a").on("mouseover", function() {
        $(".header-menu").slideDown("5000"); 
    });
	$(".header-menu").on("mouseleave", function() {
        $(".header-menu").slideUp("10000"); 
    });
	
	 var lnb = $("#main_header").offset().top;
     $(window).scroll(function() {
       var window = $(this).scrollTop();

       if(lnb <= window) {
         $("#main_header").addClass("fixed");
       } else {
         $("#main_header").removeClass("fixed");
       }
     })
});
</script>
<!-- 상단 시작 -->
<a href="${pageContext.request.contextPath}/main/main.do"> 
   <img src="${pageContext.request.contextPath}/images/main_logo.png" class="main_logo">
</a>
<div class="align-center" id="header_center">
   <a href="${pageContext.request.contextPath}/intro/eco4u.do" id="intro">Intro</a>
   <a href="${pageContext.request.contextPath}/product/list.do?category=0" id="product">Product</a> 
   <a href="${pageContext.request.contextPath}/community/list.do?c_category=1" id="community">Community</a>
   <div id="header-menu" class="header-menu">
      <div class="intro2">
         <a href="${pageContext.request.contextPath}/intro/eco4u.do" id="eco4u">ECO4U</a>
         <br><br><br> 
         <a href="${pageContext.request.contextPath}/intro/store.do" id="store">Offline Store</a>
      </div>
      <div class="product2">
         <a href="${pageContext.request.contextPath}/product/list.do?category=1" id="living">Living</a>
         <br><br> 
         <a href="${pageContext.request.contextPath}/product/list.do?category=2" id="beauty">Beauty</a>
         <br><br> 
         <a href="${pageContext.request.contextPath}/product/list.do?category=3" id="fashion">Fashion</a>
      </div>
      <div class="community2">
         <a href="${pageContext.request.contextPath}/community/list.do?c_category=1" id="communication">Communication</a>
          <br><br><br> 
         <a href="${pageContext.request.contextPath}/faq/faqlist.do" id="QnA">FAQ</a>
      </div>
   </div>
</div>
<div class="align-right" id="header_right">
   <c:if test="${!empty user}">
      [<span class="user_name">${user.id}</span>]
   </c:if>
   <c:if test="${empty user}">
      <!--<a href="${pageContext.request.contextPath}/member/registerUser.do">회원가입</a>-->
      <a href="${pageContext.request.contextPath}/member/login.do"> 
      <img src="${pageContext.request.contextPath}/images/login.png" class="login">
      </a>
   </c:if>
   <c:if test="${!empty user}">
      <a href="${pageContext.request.contextPath}/member/logout.do" class="logout"> 
      <img src="${pageContext.request.contextPath}/images/logout.png" class="logout">
      </a>
   </c:if>
   <c:if test="${!empty user && user.auth == 1}">
      <a href="${pageContext.request.contextPath}/member/myPage.do" class="home"> 
      <img src="${pageContext.request.contextPath}/images/home.png" class="home">
      </a>
      <a href="${pageContext.request.contextPath}/cart/cart.do" class="cart"> 
      <img src="${pageContext.request.contextPath}/images/cart.png" class="cart">
      </a>
      <a href="${pageContext.request.contextPath}/cart/wishList.do" class="wish"> 
      <img src="${pageContext.request.contextPath}/images/wish.png" class="wish">
      </a>
   </c:if>
   <c:if test="${!empty user && user.auth == 2}">
      <a href="${pageContext.request.contextPath}/admin/admin_list.do" class="home"> 
      <img src="${pageContext.request.contextPath}/images/home.png" class="home">
      </a>
   </c:if>
</div>

<!-- 상단 끝 -->