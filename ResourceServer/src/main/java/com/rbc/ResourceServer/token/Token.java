package com.rbc.ResourceServer.token;

import java.util.Objects;

import org.springframework.util.Assert;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;


public class Token {
	
	
	private final JWT jwt;
	
	/**
	 * Creates an instance of {@link Token}
	 * @param jwt must not be {@literal null}
	 */
	
	private Token(JWT jwt ) {
		Assert.notNull(jwt,"jwt must not be null");
		this.jwt = jwt;
	}
	
	/**
	 * Creates an instance of {@link Token} with given value 
	 * @param jwt token as {@link JWT}
	 * @return a {@link Token} instance
	 */
	
	public static Token of(JWT jwt) {
		return new Token(jwt);
			}
	
	/**
	 * 
	 * @return  token value
	 */
	public String getValue() {
		return jwt.getParsedString();
	}
		
	/**
	 * 
	 * @return JWT
	 */
	
	public JWT getJwt() {
		return jwt;
	}
	
	/**
	 * 
	 * @return JWT claim set
	 * @throws java.text.ParseException
	 */
	public JWTClaimsSet getClaimSet() throws java.text.ParseException {
		return jwt.getJWTClaimsSet();
	}
	
	@Override
	public boolean equals(Object o) {
		if(this == o) return true;
		if(o == null || getClass() != o.getClass()) return false;
		Token token = (Token) o;
		return	Objects.equals(jwt, token.jwt);
		
	}
	
//	@Override
//	public int hashCode() {
//		return Objects.hash(tokenType, jwt);
//	}
//	
	/**
	 * @return true if given this token is SignedJWT
	 */
	public boolean isSignedJWT() {
		return jwt instanceof SignedJWT;
	}
	
	/**
	 * @return Algorithm of this {@link Token}
	 */
	
	public Algorithm getAlgorithm() {
		return jwt.getHeader().getAlgorithm();
	}
}
