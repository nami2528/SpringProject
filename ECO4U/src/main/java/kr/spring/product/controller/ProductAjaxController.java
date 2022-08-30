package kr.spring.product.controller;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import kr.spring.product.service.ProductService;
import kr.spring.product.vo.P_reviewVO;
import kr.spring.product.vo.R_favVO;
import kr.spring.member.vo.MemberVO;
import kr.spring.util.PagingUtil;

@Controller
public class ProductAjaxController {

	private static final Logger logger =
			LoggerFactory.getLogger(ProductAjaxController.class);
	
	private int rowCount = 10;
	private int pageCount = 10;
	
	@Autowired
	private ProductService productService;
	
	// ========리뷰 등록=========//
	@RequestMapping("/product/writeReview.do")
	@ResponseBody
	public Map<String, String> writeReview(P_reviewVO reviewVO, HttpSession session, HttpServletRequest request) {

		logger.debug("<<리뷰 등록>> : " + reviewVO);

		Map<String, String> mapAjax = new HashMap<String, String>();

		MemberVO user = (MemberVO) session.getAttribute("user");
		if (user == null) {// 로그인 안 됨
			mapAjax.put("result", "logout");
		} else {// 로그인 됨
				// 회원번호 등록
			reviewVO.setMem_num(user.getMem_num());
			// 리뷰 등록
			productService.insertReview(reviewVO);
			mapAjax.put("result", "success");
		}
		return mapAjax;
	}

	// ==========리뷰 목록==========//
	@RequestMapping("/product/listReview.do")
	@ResponseBody
	public Map<String, Object> getList(@RequestParam(value = "pageNum", defaultValue = "1") int currentPage,
			@RequestParam int p_num) {

		logger.debug("<<currentPage>> : " + currentPage);
		logger.debug("<<p_num>> : " + p_num);

		Map<String, Object> map = new HashMap<String, Object>();
		map.put("p_num", p_num);

		// 총 글의 개수
		int count = productService.selectRowCountReview(map);

		PagingUtil page = new PagingUtil(currentPage, count, rowCount, pageCount, null);

		map.put("start", page.getStartRow());
		map.put("end", page.getEndRow());

		List<P_reviewVO> list = null;
		if (count > 0) {
			list = productService.selectListReview(map);
		} else {
			list = Collections.emptyList();
		}

		Map<String, Object> mapAjax = new HashMap<String, Object>();
		mapAjax.put("count", count);
		mapAjax.put("rowCount", rowCount);
		mapAjax.put("list", list);

		return mapAjax;
	}
	
	//==========리뷰 좋아요============//
	//리뷰 좋아요 등록
	@RequestMapping("/product/writeFav.do")
	@ResponseBody
	public Map<String,Object> writeFav(
			             R_favVO fav, HttpSession session){
		logger.debug("<<리뷰 좋아요 등록>> : " + fav);
		
		Map<String,Object> mapJson= 
				new HashMap<String,Object>();
		
		MemberVO user = 
				(MemberVO)session.getAttribute("user");
		if(user==null) {
			mapJson.put("result", "logout");
		}else {
			//로그인된 회원번호 셋팅
			fav.setMem_num(user.getMem_num());
			
			//기존에 등록된 좋아요 확인
			R_favVO reviewFav = 
					productService.selectFav(fav);
			
			if(reviewFav!=null) {//등록된 좋아요 정보가 있는 경우
				productService.deleteFav(reviewFav.getR_fav_num());
				
				mapJson.put("result", "success");
				mapJson.put("status", "noFav");
				mapJson.put("count", productService.selectFavCount(
						                      fav.getR_num()));
				
			}else {//등록된 좋아요 정보가 없는 경우
				productService.insertFav(fav);
				
				mapJson.put("result", "success");
				mapJson.put("status", "yesFav");
				mapJson.put("count", productService.selectFavCount(
						                    fav.getR_num()));
			}
		}
		return mapJson;
	}
	//리뷰 좋아요 읽기
	@RequestMapping("/product/getFav.do")
	@ResponseBody
	public Map<String,Object> getFav(
			         R_favVO fav,
			         HttpSession session){
		
		logger.debug("<<리뷰 좋아요 읽기>> : " + fav);
		
		Map<String,Object> mapJson = 
				new HashMap<String,Object>();
		
		MemberVO user = 
			  (MemberVO)session.getAttribute("user");
		if(user==null) {//로그인이 되지 않은 경우
			mapJson.put("status", "noFav");
			mapJson.put("count", productService.selectFavCount(
					                     fav.getR_num()));
		}else {//로그인 된 경우
			fav.setMem_num(user.getMem_num());
			
			//등록된 좋아요 정보 읽기
			R_favVO reviewFav = productService.selectFav(fav);
			
			if(reviewFav!=null) {//좋아요 등록
				mapJson.put("status", "yesFav");
				mapJson.put("count", productService.selectFavCount(
						                     fav.getR_num()));
			}else {//좋아요 미등록
				mapJson.put("status", "noFav");
				mapJson.put("count", productService.selectFavCount(
						                     fav.getR_num()));
			}
		}
		return mapJson;		
	}
}