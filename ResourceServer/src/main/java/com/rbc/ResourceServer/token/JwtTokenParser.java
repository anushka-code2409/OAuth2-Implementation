package com.rbc.ResourceServer.token;

import org.springframework.util.Assert;

import com.nimbusds.jose.shaded.json.parser.ParseException;
import com.nimbusds.jwt.JWTParser;

import ch.qos.logback.core.subst.Token;

public class JwtTokenParser {
	
	/**
	 * Parses a JWT token
	 * @param token token string values
	 * @return parsed {@link Token}
	 * @throws IllegalArguementException if parsing fails
	 */
	
//	public Token parse(String token) {
//		Assert.notNull(token,"Token must not be null");
//		
//		try {
//			return Token.of(JWTParser.parse(token));
//		}
//		catch(ParseException e) {
//			throw new IllegalArgumentException("Invalid token. It can't be parsed");
//		}
//	}

}
