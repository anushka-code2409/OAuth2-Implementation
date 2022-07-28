package com.rbc.ResourceServer.token;

import java.text.ParseException;

public interface TokenService {
	
	

	/**
	 * @param token the token to be validated
	 * @param ignoreExpired whether to ignore expired token
	 * @return validation response
	 * @throws ParseException 
	 */
	String validate(Token token, boolean ignoreExpired) throws ParseException;

	
	

}
