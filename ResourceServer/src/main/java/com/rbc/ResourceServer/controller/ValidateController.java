package com.rbc.ResourceServer.controller;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import com.rbc.ResourceServer.annotation.AllowedRoles;


@RestController
@CrossOrigin(origins ="*" )
public class ValidateController {

	@PostMapping("/test")
	@AllowedRoles("TestRole")
	public String tokenStatus() {		
		return" Token is validated successfully!, hello from resource";	
	}	
	
//	@PostMapping("/test1")
//	public String check() {			
//		return" Token is valid!, test controller from resource";
//	
//	}	
}
