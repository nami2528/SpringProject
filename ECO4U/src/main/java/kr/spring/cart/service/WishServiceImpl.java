package kr.spring.cart.service;

import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import kr.spring.cart.dao.WishMapper;
import kr.spring.cart.vo.WishVO;

@Service
@Transactional
public class WishServiceImpl implements WishService{

	@Autowired
	private WishMapper wishMapper;
	
	@Override
	public List<WishVO> selectList(Map<String, Object> map) {
		return wishMapper.selectList(map);
	}

	@Override
	public int selectRowCount(Map<String, Object> map) {
		return wishMapper.selectRowCount(map);
	}

	@Override
	public WishVO selectWish(Integer w_num) {
		return wishMapper.selectWish(w_num);
	}

	@Override
	public void updateWish(Integer w_num) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void deleteWish(Integer w_num) {
		// TODO Auto-generated method stub
		
	}

}
