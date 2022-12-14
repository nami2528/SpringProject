<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<style>
#zip_name{
	width:20%;
	font-size: 15px;
}
#zip_rec{
	width:15%;
	font-size: 15px;
}
#zip_cell{
	width:15%;
	font-size: 15px;
}
.zipcode{
	font-size: 15px;
}
#zipcode{
	font-size: 15px;
}
.address1{
	font-size: 15px;
}
#address1{
	font-size: 15px;
}
#address2{
	font-size: 15px;
}
#sub_btn{
	color:white;
	font-size: 25px;
	background-color: gray;
	margin-top: 30px;
	margin-bottom: 30px;
	padding: 12px;
	border: none;
	border-radius: 5px;
	width: 85%;
	font-weight: bold;
	cursor:pointer;
}
#sub_btn:hover{
	filter: brightness(95%);
}
#confirmzipcode{
	color:white;
	font-size: 13px;
	background-color: gray;
	padding: 7px;
	margin-top: -9px;
	border: none;
	border-radius: 5px;
	width: 20%;
	height:45px;
	font-weight: bold;
	cursor:pointer;
}
#confirmzipcode:hover{
	filter: brightness(95%);
}
input:focus {
	outline : 3px solid rgba(110, 131, 118, 0.45);
	border : none;
}
</style>        
<!-- 내용 시작 -->
<script type="text/javascript" src="${pageContext.request.contextPath}/js/jquery-3.6.0.min.js"></script>
<script type="text/javascript" src="${pageContext.request.contextPath}/js/confirmId.js"></script>
<div class="page-main" style="height:900px;">
	<div class="align-center" style="margin-top: 100px; margin-bottom: 30px;">
		<h1>배송지 추가</h1>
	</div>
	<form:form id="zipcodeInsert_form" action="zipcodeInsert.do" modelAttribute="zipcodeVO" style="box-shadow: 2px 2px 7px gray; border:1px solid white; border-radius:10px; width:35%; height:700px; background-color:white; padding-top:30px;">
		<form:errors element="div" cssClass="error-color"/>
		<ul>
			<li>
				<label for="zip_name" id="zip_name">배송지이름</label>
				<form:errors path="zip_name" cssClass="error-color"/><br>
			</li>
		</ul>
		<ul>
			<li>
			<div style="position:relative;">
				<form:input path="zip_name" placeholder="배송지이름을 입력해주세요 ex)집, 회사" style="width:85%; height:40px; border-radius:5px; border:1px solid gray; padding-left: 0.75rem;"/>
			</div>
			</li>
		</ul>
		<ul>
			<li>
				<label for="zip_rec" id="zip_rec">수신인</label>
				<form:errors path="zip_rec" cssClass="error-color"/><br>
			</li>
		</ul>
		<ul>
			<li>
			<div style="position:relative;">
				<form:input path="zip_rec" placeholder="수신인명을 입력해주세요" style="width:85%; height:40px; border-radius:5px; border:1px solid gray; padding-left: 0.75rem;"/>
			</div>
			</li>
		</ul>
		<ul>
			<li>
				<label for="zip_cell" id="zip_cell">전화번호</label>
				<form:errors path="zip_cell" cssClass="error-color"/><br>
			</li>
		</ul>
		<ul>
			<li>
			<div style="position:relative;">
				<form:input path="zip_cell" placeholder="전화번호를 입력해주세요" style="width:85%; height:40px; border-radius:5px; border:1px solid gray; padding-left: 0.75rem;"/>
			</div>
			</li>
		</ul>
		<ul>
			<li>
				<label for="zipcode" class="zipcode" style="width: 15%;">우편번호</label>
				<form:errors path="zipcode" cssClass="error-color"/><br>
			</li>
		</ul>
		<ul>
			<li>
			<div style="position:relative;">
				<form:input path="zipcode" placeholder="우편번호" style="width:65%; height:40px; border-radius:5px; border:1px solid gray; padding-left: 0.75rem;"/>
				<input type="button" onclick="execDaumPostcode()" value="우편번호 찾기" id="confirmzipcode">
			</div>
			</li>
		</ul>
		<ul>
			<li>
				<label for="address1" class="address1" style="width: 15%;">주소</label>
				<form:errors path="address1" cssClass="error-color"/><br>
			</li>
		</ul>
		<ul>
			<li>
			<div style="position:relative;">
				<form:input path="address1" placeholder="주소를 입력해주세요" style="width:85%; height:40px; border-radius:5px; border:1px solid gray; padding-left: 0.75rem;"/>
			</div>
			</li>
		</ul>
		<ul>
			<li>
				<label for="address2" class="address2" style="width: 15%;">상세주소</label>
				<form:errors path="address2" cssClass="error-color"/><br>
			</li>
		</ul>
		<ul>
			<li>
			<div style="position:relative;">
				<form:input path="address2" placeholder="상세주소를 입력해주세요" style="width:85%; height:40px; border-radius:5px; border:1px solid gray; padding-left: 0.75rem;"/>
			</div>
			</li>
		</ul>    
		<div class="align-center">
			<form:button id="sub_btn">배송지 추가</form:button>
		</div>                
	</form:form>
</div>
<!-- 우편번호 검색 시작 -->
<div id="layer" style="display:none;position:fixed;overflow:hidden;z-index:1;-webkit-overflow-scrolling:touch;">
<img src="//t1.daumcdn.net/localimg/localimages/07/postcode/320/close.png" id="btnCloseLayer" style="cursor:pointer;position:absolute;right:-3px;top:-3px;z-index:1" onclick="closeDaumPostcode()" alt="닫기 버튼">
</div>
<script src="http://dmaps.daum.net/map_js_init/postcode.v2.js"></script>
<script>
    // 우편번호 찾기 화면을 넣을 element
    var element_layer = document.getElementById('layer');

    function closeDaumPostcode() {
        // iframe을 넣은 element를 안보이게 한다.
        element_layer.style.display = 'none';
    }

    function execDaumPostcode() {
        new daum.Postcode({
            oncomplete: function(data) {
                // 검색결과 항목을 클릭했을때 실행할 코드를 작성하는 부분.

                // 각 주소의 노출 규칙에 따라 주소를 조합한다.
                // 내려오는 변수가 값이 없는 경우엔 공백('')값을 가지므로, 이를 참고하여 분기 한다.
                var fullAddr = data.address; // 최종 주소 변수
                var extraAddr = ''; // 조합형 주소 변수

                // 기본 주소가 도로명 타입일때 조합한다.
                if(data.addressType === 'R'){
                    //법정동명이 있을 경우 추가한다.
                    if(data.bname !== ''){
                        extraAddr += data.bname;
                    }
                    // 건물명이 있을 경우 추가한다.
                    if(data.buildingName !== ''){
                        extraAddr += (extraAddr !== '' ? ', ' + data.buildingName : data.buildingName);
                    }
                    // 조합형주소의 유무에 따라 양쪽에 괄호를 추가하여 최종 주소를 만든다.
                    fullAddr += (extraAddr !== '' ? ' ('+ extraAddr +')' : '');
                }

                // 우편번호와 주소 정보를 해당 필드에 넣는다.
                document.getElementById('zipcode').value = data.zonecode; //5자리 새우편번호 사용
                document.getElementById('address1').value = fullAddr;
                //document.getElementById('sample2_addressEnglish').value = data.addressEnglish;

                // iframe을 넣은 element를 안보이게 한다.
                // (autoClose:false 기능을 이용한다면, 아래 코드를 제거해야 화면에서 사라지지 않는다.)
                element_layer.style.display = 'none';
            },
            width : '100%',
            height : '100%',
            maxSuggestItems : 5
        }).embed(element_layer);

        // iframe을 넣은 element를 보이게 한다.
        element_layer.style.display = 'block';

        // iframe을 넣은 element의 위치를 화면의 가운데로 이동시킨다.
        initLayerPosition();
    }

    // 브라우저의 크기 변경에 따라 레이어를 가운데로 이동시키고자 하실때에는
    // resize이벤트나, orientationchange이벤트를 이용하여 값이 변경될때마다 아래 함수를 실행 시켜 주시거나,
    // 직접 element_layer의 top,left값을 수정해 주시면 됩니다.
    function initLayerPosition(){
        var width = 300; //우편번호서비스가 들어갈 element의 width
        var height = 400; //우편번호서비스가 들어갈 element의 height
        var borderWidth = 5; //샘플에서 사용하는 border의 두께

        // 위에서 선언한 값들을 실제 element에 넣는다.
        element_layer.style.width = width + 'px';
        element_layer.style.height = height + 'px';
        element_layer.style.border = borderWidth + 'px solid';
        // 실행되는 순간의 화면 너비와 높이 값을 가져와서 중앙에 뜰 수 있도록 위치를 계산한다.
        element_layer.style.left = (((window.innerWidth || document.documentElement.clientWidth) - width)/2 - borderWidth) + 'px';
        element_layer.style.top = (((window.innerHeight || document.documentElement.clientHeight) - height)/2 - borderWidth) + 'px';
    }
</script>
<!-- 우편번호 검색 끝 -->
<!-- 내용 끝 -->

