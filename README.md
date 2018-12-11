# security

使用spring security步骤

1、使用@EnableWebSecurity开启spring security框架，
使用@EnableGlobalMethodSecurity(prePostEnabled = true,securedEnabled=true,jsr250Enabled=true)开启基于方法的角色权限控制，
方法权限有三个注解：
  @Secured("USER") 由spring 提供
	@PreAuthorize("hasRole('ADMIN') AND hanRole('USER')") 由spring提供，支持springEL表达式，优先使用
	@RolesAllowed("ROLE_ADMIN") 由jsr 250 提供


2、security给我们提供了一个WebSecurityConfigurerAdapter类，该类提供了默认配置，因此我们的配置类只需要继承该类就可以了
自定义配置需要覆写三个方法：

第一个方法：
com.hou.security.config.WebSecurityConfig.configure(AuthenticationManagerBuilder auth) throws Exception
AuthenticationManagerBuilder 是AuthenticationManager对象的builder对象，可以通过该builder对象的方法构建是AuthenticationManager对象。
AuthenticationManager对象是用来认证用户提交的认证信息的，因此在配置的时候我们就应该先把我们存储的用户信息加载到内存中，或者告诉可以去哪里拿到认证信息
因此这个方法里面提供三种加载用户信息的方式：
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
		
		
		/*//二、使用数据库保存用户  注意：存在数据库中的角色名必须加上前缀ROLE_
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
		*/
		
		
		//三、自定义用户认证服务  注意：存在数据库中的角色名必须加上前缀ROLE_
		//springsecurity通过userdetailservice接口获取用户信息，改接口中只有一个loadUserByUsername方法，该方法返回一个userDetail对象，该对象保存用户的信息
		//改方式具体实现，请看我自定义的userDetailServiceImpl类
		PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
		auth.userDetailsService(userDetailsService)
		.passwordEncoder(passwordEncoder);
    
这三种加载用户信息的方式最终都会生成一个Authentication对象，该对象其实就是对用户信息的封装，供AuthenticationManager对象调用，用于认证用户信息。


第二个方法：
com.hou.security.config.WebSecurityConfig.configure(HttpSecurity http) throws Exception
该方法就是授权方法，告诉security框架那些路径需要被授权才可以访问。其实就是开启一些filter，然后对开启的filter进行配置，需要拦截那些。注意在这里可以
顺便配置路径对象的权限，这里权限有两种写法：
    //.antMatchers("/admin").hasAnyRole("USER")  这种写法，框架默认会帮我们加上ROLE_前缀
    //.antMatchers("/admin").hasAuthority("ROLE_USER")
    
当然，这里我们也可以不配置角色权限，我们可以用方法注解配置角色权限，参考方法权限，以及写法

       http
        .authorizeRequests() //注册FilterSecurityInterceptor
             .antMatchers("/index.html").permitAll()//访问index.html不要权限验证
             .anyRequest().authenticated()//其他所有路径都需要权限校验
        .and()
             .csrf().disable()//默认开启，可以显示关闭
        .formLogin()  //内部注册 UsernamePasswordAuthenticationFilter
            .loginPage("/login.html") //表单登录页面地址
            .loginProcessingUrl("/login")//form表单POST请求url提交地址，默认为/login
            .passwordParameter("password")//form表单用户名参数名
            .usernameParameter("username") //form表单密码参数名
            .successForwardUrl("/success.html")  //登录成功跳转地址
            .failureForwardUrl("/error.html") //登录失败跳转地址
            //.defaultSuccessUrl()//如果用户没有访问受保护的页面，默认跳转到页面
            //.failureUrl()
            //.failureHandler(AuthenticationFailureHandler)
            //.successHandler(AuthenticationSuccessHandler)
            //.failureUrl("/login?error")
            .permitAll();//允许所有用户都有权限访问loginPage，loginProcessingUrl，failureForwardUrl
            
第三个方法：
 com.hou.security.config.WebSecurityConfig.configure(WebSecurity web) throws Exception
 这个方法是配置security框架中那些filter的信息，以及忽略哪些路径等，直接配置所有filter
        web.ignoring().antMatchers("/js/**", "/css/**", "/images/**");


