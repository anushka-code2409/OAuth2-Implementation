package com.rbc.ResourceServer.config;

import org.mitre.jwt.signer.service.impl.JWKSetCacheService;
import org.mitre.openid.connect.client.OIDCAuthenticationFilter;
import org.mitre.openid.connect.client.OIDCAuthenticationProvider;
import org.mitre.openid.connect.client.service.AuthRequestOptionsService;
import org.mitre.openid.connect.client.service.ClientConfigurationService;
import org.mitre.openid.connect.client.service.IssuerService;
import org.mitre.openid.connect.client.service.ServerConfigurationService;
import org.mitre.openid.connect.client.service.impl.PlainAuthRequestUrlBuilder;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.util.Assert;



public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	private final OIDCAuthenticationProvider openIdConnectAuthenticationProvider;
	private final ServerConfigurationService serverConfigurationService;
	private final ClientConfigurationService clientConfigService;
	private final IssuerService issuerService;
	private final AuthRequestOptionsService authRequestOptionsService;
	
	public SecurityConfig(OIDCAuthenticationProvider openIdConnectAuthenticationProvider,ServerConfigurationService serverConfigurationService,ClientConfigurationService clientConfigService, IssuerService issuerService,AuthRequestOptionsService authRequestOptionsService) {
				
		Assert.notNull(openIdConnectAuthenticationProvider, "Issuer service must not be null");
		Assert.notNull(serverConfigurationService, "Issuer service must not be null");
		Assert.notNull(clientConfigService, "Issuer service must not be null");
		Assert.notNull(issuerService, "Issuer service must not be null");
		Assert.notNull(authRequestOptionsService, "authRequestOptions service must not be null");
		
		this.openIdConnectAuthenticationProvider = openIdConnectAuthenticationProvider;
		this.serverConfigurationService = serverConfigurationService;
		this.clientConfigService = clientConfigService;
		this.issuerService = issuerService;
		this.authRequestOptionsService = authRequestOptionsService;
	}
	
	@ConditionalOnMissingBean
	@Bean
	
	public OIDCAuthenticationFilter authenticationFilter() throws Exception {
		OIDCAuthenticationFilter filter = new OIDCAuthenticationFilter();
		filter.setAuthenticationManager(authenticationManager());
		filter.setIssuerService(issuerService);
		filter.setServerConfigurationService(serverConfigurationService);
		filter.setClientConfigurationService(clientConfigService);
		filter.setAuthRequestUrlBuilder(new PlainAuthRequestUrlBuilder());
		filter.setValidationServices(new JWKSetCacheService());
		filter.setAuthRequestOptionsService(authRequestOptionsService);
		
		return filter;
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) {
		auth.authenticationProvider(openIdConnectAuthenticationProvider);
	} 

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
		    .anyRequest().authenticated()
		    .and()
		    .exceptionHandling()
		    .and()
		    .addFilterBefore(authenticationFilter(), AbstractPreAuthenticatedProcessingFilter.class)
		    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);
		
	}
}
