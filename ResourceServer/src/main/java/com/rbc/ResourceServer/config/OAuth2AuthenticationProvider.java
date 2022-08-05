package com.rbc.ResourceServer.config;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;

public class OAuth2AuthenticationProvider implements AuthenticationProvider {
	
	@Override
    public Authentication authenticate(Authentication authentication) { return authentication;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthentication.class.isAssignableFrom(authentication);
    }

}
