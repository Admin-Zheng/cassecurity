package com.hou.security.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.hou.security.compemt.UserDetailServiceImpl;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	
	//使用自定义用户验证服务时使用
	@Autowired
	private UserDetailsService userDetailsService;
	
	//使用数据库时导入打datasource,只有是使用数据库认证用户时才会有这个
	@Autowired
	private DataSource dataSource;
	//指定通过用户名查询密码sql
	String pwdQuery = "SELECT user_name,pwd,avalibale FROM t_user WHERE user_name=?";
	//指定通过用户名查询角色sql
	String roleQuery = "SELECT u.user_name,r.role_name FROM t_user u,t_role r,t_user_role ur WHERE u.id=ur.user_id AND r.id=ur.role_id AND u.user_name=?";
	
	
	/* 用来配置用户签名服务，也就是配置用户登录验证，主要是用user-details机制，并且在此接口中还可以配置用户角色
	 * 
	 * 用户信息可以有两种方式加载到spring-security中。一种是使用内存用户，既把用户名和密码直接硬编码。一种是使用jdbc用户，即把
	 * 用户名和密码放在数据库中，然后通过userdetail加载到springsecurity中
	 * 
	 * 
	 *  @param AuthenticationManagerBuilder 认证管理器构造器，该builder主要构建用户具体的权限控制
	 * @see org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter#configure(org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder)
	 */
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		/*//一、使用内存用户
		
		//spring5中所有密码都需要编码器，因此不能使用明文密码了
		
		//roles方法会自动给设定的角色加上ROLE_的前缀，比如设置角色为USER，那么在spring security框架中的，角色为ROLE_USER
		
		//1、创建密码编码器，不管怎样密码肯定不是明文，因此需要密码编码器
		PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
		//2、设置使用内存写入用户信息
		auth.inMemoryAuthentication()
			//3、设置密码编码器
			.passwordEncoder(passwordEncoder)
			//4、设置用户
			.withUser("admin")
			//注意改密码一定要是密码编码器加密后的字符串  abc
			.password("$2a$10$ho.HXLXWT5y0hHMkTLJcauXlHmipL/lSjT9COXPNIVUk5.XMnyTAW")
			.roles("ADMIN")
		
		//and起连接作用，连接下一个用户信息
		.and()
		.withUser("user")
		//密码123456
		.password("$2a$10$11sQYFK1sLGb4D5B5oZwWeKSF1URf8dlqXU/PDe7DS7ecCdYeqVMC")
		.roles("USER");
		*/
		
		
		//二、使用数据库保存用户
		//1、创建密码编码器，不管怎样密码肯定不是明文，因此需要密码编码器
		PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
		//使用数据库认证
		auth.jdbcAuthentication()
			//设置密码编码器
			.passwordEncoder(passwordEncoder)
			//设置数据源
			.dataSource(dataSource)
			//设置验证密码的sql
			.usersByUsernameQuery(pwdQuery)
			//设置获取角色的sql，改sql返回多条数据，该用户会被设置多个权限
			.authoritiesByUsernameQuery(roleQuery);
		
		
		
		/*//三、自定义用户认证服务
		//springsecurity通过userdetailservice接口获取用户信息，改接口中只有一个loadUserByUsername方法，该方法返回一个userDetail对象，该对象保存用户的信息
		//改方式具体实现，请看我自定义的userDetailServiceImpl类
		PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
		auth.userDetailsService(userDetailsService)
		.passwordEncoder(passwordEncoder);*/
		
	}
	/* 用来配置拦截保护的请求，哪些是需要验证的，哪些是不需要验证，哪些是需要特定角色验证的
	 * 该接口通过角色配置用户的权限
	 * authorizeRequests()该方法后配置只对认证成功的，并且拥有改角色的用户访问的权限地址
	 * anyRequest()该方法配置任何请求，都可以访问，不管该请求是否来自认证用户
	 * authenticated()该方法配置对签名用户成功的访问路径
	 * 
	 * 
	 * @see org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter#configure(org.springframework.security.config.annotation.web.builders.HttpSecurity)
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		//注意：在这里先把需要权限的路径全部在第一阶段配进来，具体路径需要的权限在controller上@PreAuthorize("hasRole('USER')")注解体现
		//第二阶段中，把没有配置权限路径全部放行
		//springsecurity会自动按照第一阶段配置为主
		
		
		//先限定签名后的请求
		/* ####第一阶段，先把需要认证的权限付给角色#### */
		http.authorizeRequests()
			//限定"/user/welcom","/user/detail" 这两个路径只有"USER"角色可以访问
			//.antMatchers("/user/welcom","/user/detail").hasAnyRole("USER")
			.antMatchers("/user/welcom","/user/detail").authenticated()
			//限定"/admin/**"路径，只有拥有ADMIN角色的才可以访问
			//.antMatchers("/admin").hasAuthority("ROLE_ADMIN")
			.antMatchers("/admin").authenticated()
			//其他路径需要签名后才可以访问
			//.anyRequest().authenticated()
			//其他路径都允许访问，但是这里请求的前提已经是签名了的，所以整合起来就是其他路径签名后访问
			.anyRequest().permitAll()
			/* ######第二阶段，开启没有配置权限的其他请求 #######*/
			.and().anonymous()
			/* ######第三阶段，使用spring security默认登录页面，开启基本http基础验证 #######*/
			.and()
			.formLogin()
			.and().httpBasic();
		
		//关闭跨域访问
		http.csrf().disable();
	}
	//
	
	
	/* 用来配置filter链
	 * @see org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter#configure(org.springframework.security.config.annotation.web.builders.WebSecurity)
	 */
	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/js/**", "/css/**", "/images/**");
	}
	
	
	public static void main(String[] args) {
		String encode = new BCryptPasswordEncoder().encode("123456");
		System.out.println(encode);
	}
	

}
