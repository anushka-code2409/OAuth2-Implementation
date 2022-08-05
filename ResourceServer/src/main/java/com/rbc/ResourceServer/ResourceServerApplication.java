package com.rbc.ResourceServer;


import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RestController;


@RestController
@SpringBootApplication
public class ResourceServerApplication {

	
	public static void main(String[] args) {
		SpringApplication.run(ResourceServerApplication.class, args);
	}
	
	
}
