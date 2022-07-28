package com.rbc.ResourceServer.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ValidateController {

	@RequestMapping("/test")
	public String test() {
		return "Token is valid!";
	}
}
