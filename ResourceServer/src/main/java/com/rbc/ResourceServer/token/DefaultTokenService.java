package com.rbc.ResourceServer.token;

import java.sql.Date;
import java.text.ParseException;

import org.apache.commons.logging.Log;
import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.jwt.signer.service.impl.JWKSetCacheService;
import org.mitre.oauth2.model.RegisteredClient;
import org.mitre.openid.connect.client.OIDCAuthenticationFilter;
import org.mitre.openid.connect.client.service.ClientConfigurationService;
import org.mitre.openid.connect.client.service.ServerConfigurationService;
import org.mitre.openid.connect.config.ServerConfiguration;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.util.Assert;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.rbc.ResourceServer.config.OAuthEndpoints;

import ch.qos.logback.classic.Logger;


public class DefaultTokenService implements TokenService {

	private final ClientConfigurationService clientConfigurationService;
	private final OAuthEndpoints oauthEndpoints;
	private final OIDCAuthenticationFilter authFilter;
	private final ServerConfigurationService serverConfigurationService;
	
	private static final int timeSkewAllowance = 300;
	
	private final JWKSetCacheService validationServices;
	
	private final static org.slf4j.Logger log = LoggerFactory.getLogger(DefaultTokenService.class);
	
	/**
	 * Creates an instance of {@link DefaultTokenService}
	 * 
	 * @param clientConfigurationService must not be {@literal null}
	 * @param oauthEndpoints must not be {@literal null}
	 * @param authFilter must not be {@literal null}
	 * @param serverConfigurationService must not be {@literal null}
	 */
	
	public DefaultTokenService(ClientConfigurationService clientConfig,OAuthEndpoints oauthEndpoints,OIDCAuthenticationFilter authFilter,ServerConfigurationService serverConfigurationService) {
		
		Assert.notNull(clientConfig,"clientConfigurationService must not be null");
		Assert.notNull(oauthEndpoints," OAuthEndpoints must not be null");
		Assert.notNull(authFilter,"OIDCAuthenticationFilter must not be null");
		Assert.notNull(serverConfigurationService,"serverConfigurationService must not be null");
		
		this.clientConfigurationService = clientConfig;
		this.oauthEndpoints = oauthEndpoints;
		this.authFilter = authFilter;
		this.serverConfigurationService = serverConfigurationService;
		this.validationServices = new JWKSetCacheService();
		
	}
	
	/**
	 * @param token the token to be validated
	 * @param ignoreExpired whether to ignore expired token
	 * @return validation response
	 * @throws ParseException 
	 */
	
		
	@Override
	public String validate(Token token, boolean ignoreExpired) throws ParseException {
		// TODO Auto-generated method stub
		
		if(!token.isSignedJWT()) {
			throw new IllegalStateException("Token is not signed");
		}
		
		SignedJWT signedIdToken = (SignedJWT) token.getJwt();
		
		//check the signature
		JWTSigningAndValidationService jwtValidator = null;
		Algorithm tokenAlg = token.getAlgorithm();
		
		if(tokenAlg.equals(JWSAlgorithm.HS256)
				||tokenAlg.equals(JWSAlgorithm.HS384)
				||tokenAlg.equals(JWSAlgorithm.HS512)) {
			
			//generate on based on client secret
//			jwtValidator = authFilter.getSymmetricCacheService().getSymmetricValidtor(getClientConfiguration.getClient());
		}else {
			//otherwise load from server's public key
			jwtValidator = validationServices.getValidator(getJwksUri());
		}
		
		if(jwtValidator != null) {
			if(!jwtValidator.validateSignature(signedIdToken)) {
				throw new AuthenticationServiceException("Signature validation failed");
			}
		}
		else {
//				Log.error("No validation service found. Skipping signature validation");
				throw new AuthenticationServiceException("Unable to find an appropriate signature validator for Token");
			}
		//test the attributes of the access token
		JWTClaimsSet accessClaims = token.getClaimSet();
		String issuerUrl = getIssuerUrl(token);
		// check the issuer
		
		if(accessClaims.getIssuer() == null) {
			throw new AuthenticationServiceException("Access Token is null");
		} else if(!accessClaims.getIssuer().equals(issuerUrl)) {
			throw new AuthenticationServiceException("Issuers do not match, expected" +issuerUrl + "got" + accessClaims.getIssuer());
		}
		
		boolean expired = false;
		//check expiration
		if(accessClaims.getExpirationTime() == null) {
			throw new AuthenticationServiceException("Access token does not have required expiration claim");
		}else {
			// its not null, see if it's expired
			Date now = new Date(System.currentTimeMillis() - (timeSkewAllowance * 1000));
			if (now.after(accessClaims.getExpirationTime())) {
				if(!ignoreExpired) {
					throw new AuthenticationServiceException("Access token is expired:" + accessClaims.getExpirationTime());
				}else {
					expired = true;
				}
			}
		}
		
		//check not before
		if(accessClaims.getNotBeforeTime() != null) {
			Date now = new Date(System.currentTimeMillis() - (timeSkewAllowance * 1000));
			if (now.before(accessClaims.getExpirationTime())) {
				throw new AuthenticationServiceException("Access token is not valid until:" + accessClaims.getNotBeforeTime());
			}
		}
		JsonObject obj = new Gson().fromJson(signedIdToken.getPayload().toString(), JsonObject.class );
		//check issued at
			if(accessClaims.getIssueTime() == null) {
				
						throw new AuthenticationServiceException("Access token does not have required issued-at claim");		
			}else {
				//since it's not null, see if it was issued in the future
				Date now = new Date(System.currentTimeMillis() + (timeSkewAllowance * 1000));
				if (now.before(accessClaims.getIssueTime())) {
					throw new AuthenticationServiceException("Access token was issued in the future" + accessClaims.getIssueTime());
				}
				
			}
			obj.add("active", new JsonPrimitive(!expired));
				
		
		
		return obj.toString();
	}
	
	/**
	 * Returns JWKs URI
	 * @return
	 */
	
	private String getJwksUri() {
		return oauthEndpoints.getIssuerURL();
	}
	
	/**
	 * Returns {@link RegisteredClient}
	 * @return
	 */
	
//	private RegisteredClient getClientConfiguration() {
//		ServerConfiguration serverConfiguration = serverConfiguration.getServerConfiguration(oauthEndpoints.getIssuerURL());
//		return clientConfigurationService.getClientConfiguration(serverConfiguration);
//	}
	
	private String getIssuerUrl(Token token) {
		return oauthEndpoints.getIssuerURL();
	}

}
