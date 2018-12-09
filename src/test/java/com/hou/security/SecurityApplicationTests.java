package com.hou.security;

import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import com.alibaba.fastjson.JSON;
import com.hou.security.mapper.UserMapper;

@RunWith(SpringRunner.class)
@SpringBootTest
public class SecurityApplicationTests {
	
	@Autowired
	private UserMapper UserMapper;

	@Test
	public void contextLoads() {
		
		System.out.println(JSON.toJSONString(UserMapper.findByUsername("zhangsan")));
		
	}

}
