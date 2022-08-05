package com.rbc.ResourceServer.config;

import org.springframework.security.authentication.AbstractAuthenticationToken;

import com.rbc.ResourceServer.token.AccessToken;

public class JwtAuthentication  extends AbstractAuthenticationToken {

	private final AccessToken accessToken;

    public JwtAuthentication(AccessToken accessToken) {
        super(accessToken.getAuthorities());
        this.accessToken = accessToken;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return accessToken.getValueAsString();
    }
}
