package com.hou.security.compemt;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.hou.security.mapper.UserMapper;
import com.hou.security.pojo.Role;
import com.hou.security.pojo.User;

/**
 * 该类为springsecurity框架自定义认证服务的类
 * 认证服务可以从内存中加载，也可以从数据库中读取
 * 还可以自定义方式思想，该类就是通过自定义方式实现认证
 * 
 * 要指定实现认证服务，需要实现userDetailService接口，该接口中只有loadUserByUsername方法，该方法返回userDetail对象，该对象保存用户信息
 *
 */
@Service
public class UserDetailServiceImpl implements UserDetailsService {
	
	@Autowired
	private UserMapper UserMapper;

	/* 该方法中需要返回一个userdetail对象
	 * userdetail是个接口，而该接口中实现类是User，user对象的构建需要username，password，以及一个该用户权限的collection
	 * @see org.springframework.security.core.userdetails.UserDetailsService#loadUserByUsername(java.lang.String)
	 */
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		User user = UserMapper.findByUsername(username);
		
		List<GrantedAuthority> authorities = new ArrayList<>();
		
		//将角色转换成可以识别的
		for (Role role : user.getRoles()) {
			
			authorities.add(new SimpleGrantedAuthority(role.getRolename()));
			
		}
		//将用户名，密码，以及角色构建成userdetails
		UserDetails userDetails = new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPwd(), authorities);
		
		return userDetails;
		
	}

}
