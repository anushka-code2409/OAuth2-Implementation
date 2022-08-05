package com.rbc.ResourceServer.config;

import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwk.JwkProvider;
import com.rbc.ResourceServer.exception.AccessTokenAuthenticationFailureHandler;
import com.rbc.ResourceServer.exception.AuthorizationAccessDeniedHandler;
import com.rbc.ResourceServer.token.JwtTokenValidator;

import lombok.RequiredArgsConstructor;

@Order(1)
@EnableWebSecurity
@RequiredArgsConstructor

public class SecurityConfig extends WebSecurityConfigurerAdapter {

	 @Value("${spring.security.ignored}")
	    private String nonSecureUrl;

	    @Value("${jwk}")
	    private String jwkProviderUrl;
	    

	    @Override
	    protected void configure(HttpSecurity http) throws Exception {
	        http
	                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
	                .and()
	                .csrf().disable()
	                .cors()
	                .and()
	                .exceptionHandling()
	                .accessDeniedHandler(accessDeniedHandler())
	                .and()
	                .addFilterBefore(
	                        new AccessTokenFilter(
	                                jwtTokenValidator(OAuth2JWKProvider()),
	                                authenticationManagerBean(),
	                                authenticationFailureHandler()),
	                        BasicAuthenticationFilter.class);
	    }

	    @Override
	    public void configure(WebSecurity web) {
	        web.ignoring().antMatchers(nonSecureUrl);
	    }

	    @SuppressWarnings("EmptyMethod")
	    @ConditionalOnMissingBean
	    @Bean
	    @Override
	    public AuthenticationManager authenticationManagerBean() throws Exception {
	        return super.authenticationManagerBean();
	    }

	    @Override
	    public void configure(AuthenticationManagerBuilder auth) {
	        auth.authenticationProvider(authenticationProvider());
	    }

	    @Bean
	    public AuthenticationProvider authenticationProvider() {
	        return new OAuth2AuthenticationProvider();
	    }

	    @Bean
	    public AuthenticationFailureHandler authenticationFailureHandler() {
	        return new AccessTokenAuthenticationFailureHandler();
	    }

	    @Bean
	    public JwtTokenValidator jwtTokenValidator(JwkProvider jwkProvider) {
	        return new JwtTokenValidator(jwkProvider);
	    }

	    @Bean
	    public JwkProvider OAuth2JWKProvider() {
	        return new OAuth2JWKProvider(jwkProviderUrl);
	    }

	    @Bean
	    public AccessDeniedHandler accessDeniedHandler() {
	        return new AuthorizationAccessDeniedHandler();
	    }
}
