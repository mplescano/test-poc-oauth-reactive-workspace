package com.mplescano.apps.poc.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.expression.OAuth2ExpressionUtils;

public class FacadeOauth2Handler {

    public boolean hasScope(Authentication authentication, String scope) {
        return OAuth2ExpressionUtils.hasAnyScope(authentication, new String[]{ scope });
    }
    
    public boolean hasAnyScope(Authentication authentication, String... scopes) {
        return OAuth2ExpressionUtils.hasAnyScope(authentication, scopes);
    }
    
    public boolean hasScopeMatching(Authentication authentication, String scopeRegex) {
        return OAuth2ExpressionUtils.hasAnyScopeMatching(authentication, new String[]{ scopeRegex });
    }
    
    public boolean hasAnyScopeMatching(Authentication authentication, String... scopesRegex) {
        return OAuth2ExpressionUtils.hasAnyScopeMatching(authentication, scopesRegex);
    }
    
    public boolean denyOAuthClient(Authentication authentication) {
        return !OAuth2ExpressionUtils.isOAuth(authentication);
    }
}
