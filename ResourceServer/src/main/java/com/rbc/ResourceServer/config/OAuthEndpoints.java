package com.rbc.ResourceServer.config;

import org.springframework.beans.factory.annotation.Autowired;

public class OAuthEndpoints {
	
		private String issuerURL;
		
		public OAuthEndpoints(){
			
		}
		public String getIssuerURL(){
			return issuerURL;			
		}
		
		public void setIssuerURL(String issuerURL){
			this.issuerURL = issuerURL;
		}
		
//		public String getaltIssuerURL(){
//			return altIssuerURL;			
//		}
	//	
//		public void setaltIssuerURL(String altIssuerURL){
//			this.altIssuerURL = altIssuerURL;
//		}
	}



