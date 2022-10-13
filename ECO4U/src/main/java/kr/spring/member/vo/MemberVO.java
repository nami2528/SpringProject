package kr.spring.member.vo;

import java.sql.Date;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

public class MemberVO {
	private int mem_num;
	@Pattern(regexp="^(?=.*[A-Za-z])(?=.*\\d)[A-Za-z\\d]{6,20}")
	private String id;
	private int auth;
	@NotEmpty
	private String mem_name;
	@Pattern(regexp="^[A-Za-z0-9]{4,12}$")
	private String mem_pw;
	@NotEmpty
	private String mem_cell;
	@Email
	@NotEmpty
	private String mem_email;
	@Size(min=5,max=5)
	private String zipcode;
	@NotEmpty
	private String address1;
	@NotEmpty
	private String address2;
	private Date reg_date;
	private Date modify_date;
	
	//비밀번호 변경시 현재 비밀번호를 저장하는 용도
	@Pattern(regexp="^[A-Za-z0-9]{4,12}$")
	private String mem_pwcheck;
	
	//비밀번호 변경시 현재 비밀번호를 저장하는 용도
	@Pattern(regexp="^[A-Za-z0-9]{4,12}$")
	private String now_passwd;
	
	//=========비밀번호 일치 여부 체크===========//
	public boolean isCheckedPasswd(String userPasswd) {
		if(auth > 0 && mem_pw.equals(userPasswd)) {
			return true;
		}
		return false;
	}
	
	//=========전화번호 일치 여부 체크===========//
	public boolean isCheckedcall(String userCall) {
		if(auth > 0 && mem_cell.equals(userCall)) {
			return true;
		}
		return false;
	}
	
	//=========이에일 일치 여부 체크===========//
	public boolean isCheckedemail(String userEmail) {
		if(auth > 0 && mem_email.equals(userEmail)) {
			return true;
		}
		return false;
	}
	
	//=========아이디 일치 여부 체크===========//
	public boolean isCheckedid(String userId) {
		if(auth > 0 && id.equals(userId)) {
			return true;
		}
		return false;
	}
		
	public int getMem_num() {
		return mem_num;
	}

	public void setMem_num(int mem_num) {
		this.mem_num = mem_num;
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public int getAuth() {
		return auth;
	}

	public void setAuth(int auth) {
		this.auth = auth;
	}

	public String getMem_name() {
		return mem_name;
	}

	public void setMem_name(String mem_name) {
		this.mem_name = mem_name;
	}

	public String getMem_pw() {
		return mem_pw;
	}

	public void setMem_pw(String mem_pw) {
		this.mem_pw = mem_pw;
	}

	public String getMem_cell() {
		return mem_cell;
	}

	public void setMem_cell(String mem_cell) {
		this.mem_cell = mem_cell;
	}

	public String getMem_email() {
		return mem_email;
	}

	public void setMem_email(String mem_email) {
		this.mem_email = mem_email;
	}

	public String getZipcode() {
		return zipcode;
	}

	public void setZipcode(String zipcode) {
		this.zipcode = zipcode;
	}

	public String getAddress1() {
		return address1;
	}

	public void setAddress1(String address1) {
		this.address1 = address1;
	}

	public String getAddress2() {
		return address2;
	}

	public void setAddress2(String address2) {
		this.address2 = address2;
	}

	public Date getReg_date() {
		return reg_date;
	}

	public void setReg_date(Date reg_date) {
		this.reg_date = reg_date;
	}

	public Date getModify_date() {
		return modify_date;
	}

	public void setModify_date(Date modify_date) {
		this.modify_date = modify_date;
	}

	public String getNow_passwd() {
		return now_passwd;
	}

	public void setNow_passwd(String now_passwd) {
		this.now_passwd = now_passwd;
	}

	public String getMem_pwcheck() {
		return mem_pwcheck;
	}

	public void setMem_pwcheck(String mem_pwcheck) {
		this.mem_pwcheck = mem_pwcheck;
	}
	
}
