package com.rbc.ResourceServer.config;

import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;



@Component
@Configuration(value = "client-details")
public class Client_details {

	
	public String clientSecret;
	public String clientId;
	public Set<String> grantType;
	public String tenant_id;
  
	@Autowired
   public Client_details() {}
  
  
  	
   public String getClientSecret(){
		return clientSecret;
	}
	
	public void setClientSecret(String clientSecret){
		this.clientSecret = clientSecret;
	}
	
	public String getClientId(){
		return clientId;
	}
	
	public void setClientId(String clientId){
		this.clientId = clientId;
	}
	
	public Set<String> getgrantType(){
		return grantType;
	}
	
	public void setgrantType(Set<String> grantType){
		this.grantType = grantType;
	}
      
      public String getTenantId() {
      	return tenant_id;
      }
      public void setTenantId(String tenant_id) {
      	this.tenant_id = tenant_id;
      } 
      
  	

}
