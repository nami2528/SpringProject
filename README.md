# SpringProject
Spring project
[장바구니 - 상품 선택 삭제 오류]
 : 체크박스로 선택한 상품들을 배열에 담아서 가져오려는데 값이 안불러와짐
[해결]
<img width="654" alt="스크린샷 2022-10-21 오후 6 12 58" src="https://user-images.githubusercontent.com/109573488/197809445-e9883613-5dc2-4a15-a13f-e1ba65ad3330.png">
array로 설정했던 체크박스 값을 .toString으로 변환해서 controller로 전송
<img width="662" alt="스크린샷 2022-10-21 오후 6 12 24" src="https://user-images.githubusercontent.com/109573488/197809693-70b54768-f6ec-4ce2-be3d-e3a5c6c931ee.png">

service에 String del_product 값을 받는 deleteCartchecked를 생성한 뒤
string 값으로 받은 배열을 구분자 ,로 split해서 값을 가져옴
split로 가져온 값을 반복문으로 장바구니에서 delete함

