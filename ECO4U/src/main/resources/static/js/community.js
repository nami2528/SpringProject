$(function(){

 	//=====검색 유효성 체크 =====//
	$('#search_form').submit(function(){
		if($('#keyword').val().trim()==''){
			alert('검색어를 입력하세요!');
			$('#keyword').val('').focus();
			return false;
			}
			});
			
	
			
	//===== 사진 처리 ======//
	//확인 버튼 처리
	$('#photo_btn').click(function(){
		$('#photo_choice').show(); //수정 폼 노출
		$(this).hide(); //수정 버튼 감추기
	});
	
	//처음 화면에 보여지는 이미지 읽기
	let photo_path = $('.com-photo').attr('src');
	let com_photo; //업로드하고자 선택한 이미지 저장
	$('#upload').change(function(){
		com_photo = this.files[0];
		if(!com_photo){ //파일 정보가 없는 경우
			$('.com-photo').attr('src', photo_path);
			return;
		}
		//파일 용량 체크
		if(com_photo.size > 2048*2048){
			alert(Math.round(com_photo.size/1024) + 
							'kbytes(2048kbytes까지만 업로드 가능)');
			//원래 이미지로 교체
			$('.com-photo').attr('src', photo_path);
			$(this).val(''); //파일명 지우기
			return;
		}
		
		//이미지 미리보기 처리
		let reader = new FileReader();
		//선택한 이미지 읽기
		reader.readAsDataURL(com_photo);
		
		reader.onload=function(){
			//읽어들인 이미지 표시
			$('.com-photo').attr('src', reader.result);
		};
	});//end of change
	
	//취소 버튼 처리
	$('#photo_reset').click(function(){
		$('.com-photo').attr('src',photo_path);
		$('#upload').val('');
	});
	
	//게시글 등록 유효성 체크
	$('#register_form').submit(function(event){
		if($('#c_title').val().trim()==''){
			alert('제목을 입력하세요');
			$('#c_title').val('').focus();
			return false;
		}else if($('#c_content').val().trim()==''){
			alert('내용을 입력하세요');
			$('#c_content').val('').focus();
			return false;
		}
		
	});

});