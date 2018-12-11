package com.hou.security.controller;

import javax.annotation.security.RolesAllowed;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {
	
	@PreAuthorize("hasRole('USER')")
	@RequestMapping("/user/welcom")
	public String welcom() {
		
		return "welcom";
		
	}
	
	@PreAuthorize("hasRole('USER')")
	@RequestMapping("/user/detail")
	public String detail() {
		
		return "detail";
		
	}
	
	@RequestMapping("/index")
	public String index() {
		
		return "index";
		
	}
	
	@RolesAllowed("ROLE_ADMIN")
	@RequestMapping("/admin")
	public String admin() {
		
		return "admin";
		
	}
	
}
