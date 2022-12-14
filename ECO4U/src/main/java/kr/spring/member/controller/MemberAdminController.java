package kr.spring.member.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import kr.spring.member.service.MemberService;
import kr.spring.member.vo.MemberVO;
import kr.spring.util.PagingUtil;

@Controller
public class MemberAdminController {
	private static final Logger logger = LoggerFactory.getLogger(MemberAdminController.class);
	
	private int rowCount=10;
	private int pageCount=10;	
	
	@Autowired
	private MemberService memberService;
	
	//==========회원목록==========//
	//전체 회원 조회
	@RequestMapping("/admin/admin_list.do")
	public ModelAndView processAll(@RequestParam(value="pageNum", defaultValue="1")int currentPage,
								@RequestParam(value="keyfield", defaultValue="")String keyfield,
								@RequestParam(value="keyword", defaultValue="")String keyword,
								HttpSession session, Model model) {
		//로그인 정보 불러오기
		MemberVO user = (MemberVO)session.getAttribute("user");
		MemberVO admin = memberService.selectMember(user.getMem_num());
		model.addAttribute("admin", admin);
		
		Map<String,Object> map = new HashMap<String, Object>();
		map.put("keyfield", keyfield);
		map.put("keyword", keyword);
		
		//총 글의 개수 또는 검색된 글의 개수
		int count = memberService.selectRowCount(map);
		
		logger.debug("<<count>>: "+count);
		
		//페이지 처리
		PagingUtil page = new PagingUtil(keyfield, keyword, currentPage, count, rowCount, pageCount, "admin_list.do");
		map.put("start", page.getStartRow());
		map.put("end", page.getEndRow());
		
		List<MemberVO> list = null;
		if(count > 0)
			list = memberService.selectList(map);
		
		ModelAndView mav = new ModelAndView();
		mav.setViewName("admin_memList");
		mav.addObject("count",count);
		mav.addObject("list", list);
		mav.addObject("page", page.getPage());
		
		return mav;
	}
	
	//탈퇴 회원 조회
	@RequestMapping("/admin/delete_list.do")
	public ModelAndView processDel(@RequestParam(value="pageNum", defaultValue="1")int currentPage,
								   @RequestParam(value="keyfield", defaultValue="")String keyfield,
								   @RequestParam(value="keyword", defaultValue="")String keyword,
								   HttpSession session, Model model) {
		//로그인 정보 불러오기
		MemberVO user = (MemberVO)session.getAttribute("user");
		MemberVO admin = memberService.selectMember(user.getMem_num());
		model.addAttribute("admin", admin);
		
		Map<String,Object> map = new HashMap<String, Object>();
		map.put("keyfield", keyfield);
		map.put("keyword", keyword);

		//총 글의 개수 또는 검색된 글의 개수
		int count = memberService.selectDelCount(map);

		logger.debug("<<count>>: "+count);

		//페이지 처리
		PagingUtil page = new PagingUtil(keyfield, keyword, currentPage, count, rowCount, pageCount, "admin_list.do");
		map.put("start", page.getStartRow());
		map.put("end", page.getEndRow());

		List<MemberVO> list = null;
		if(count > 0)
			list = memberService.selectDelList(map);

		ModelAndView mav = new ModelAndView();
		mav.setViewName("admin_delList");
		mav.addObject("count",count);
		mav.addObject("list", list);
		mav.addObject("page", page.getPage());

		return mav;
	}

	//========회원정보수정=========//
	//회원정보 조회
	@GetMapping("/admin/admin_detail.do")
	public String memDetail(@RequestParam int mem_num,Model model,HttpSession session, Model model_2) {
		//로그인 정보 불러오기
		MemberVO user = (MemberVO)session.getAttribute("user");
		MemberVO admin = memberService.selectMember(user.getMem_num());
		model_2.addAttribute("admin", admin);
		
		MemberVO memberVO = memberService.selectMember(mem_num);
		model.addAttribute("memberVO", memberVO);

		return "admin_memDetail";
	}

	//회원정보 수정
	@GetMapping("/admin/admin_modify.do")
	public String memModiForm(@RequestParam int mem_num,Model model,HttpSession session, Model model_2) {
		//로그인 정보 불러오기
		MemberVO user = (MemberVO)session.getAttribute("user");
		MemberVO admin = memberService.selectMember(user.getMem_num());
		model_2.addAttribute("admin", admin);

		MemberVO memberVO = memberService.selectMember(mem_num);
		model.addAttribute("memberVO", memberVO);

		return "admin_memModify";
	}

	//수정 폼에서 전송된 데이터 처리
	@PostMapping("/admin/admin_update.do")
	public String submit(MemberVO memberVO, Model model, HttpServletRequest request) {
		logger.debug("<<관리자 회원등급 수정>>: "+memberVO);

		//회원정보 수정
		memberService.updateByAdmin(memberVO);

		//View에 표시할 메시지
		model.addAttribute("message", "회원등급 수정 완료!");
		model.addAttribute("url", request.getContextPath()+"/admin/admin_detail.do?mem_num="+memberVO.getMem_num());

		return "common/resultView";
	}
	
}
