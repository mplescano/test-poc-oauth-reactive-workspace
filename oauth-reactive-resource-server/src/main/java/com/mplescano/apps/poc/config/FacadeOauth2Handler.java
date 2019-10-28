package com.mplescano.apps.poc.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.expression.OAuth2SecurityExpressionMethods;

public class FacadeOauth2Handler {

    public boolean hasScope(Authentication authentication, String scope) {
        OAuth2SecurityExpressionMethods oauth2 = new OAuth2SecurityExpressionMethods(authentication);
        return oauth2.hasScope(scope);
    }
    
    public boolean hasAnyScope(Authentication authentication, String... scopes) {
        OAuth2SecurityExpressionMethods oauth2 = new OAuth2SecurityExpressionMethods(authentication);
        return oauth2.hasAnyScope(scopes);
    }
    
    public boolean hasScopeMatching(Authentication authentication, String scopeRegex) {
        OAuth2SecurityExpressionMethods oauth2 = new OAuth2SecurityExpressionMethods(authentication);
        return oauth2.hasScope(scopeRegex);
    }
    
    public boolean hasAnyScopeMatching(Authentication authentication, String... scopesRegex) {
        OAuth2SecurityExpressionMethods oauth2 = new OAuth2SecurityExpressionMethods(authentication);
        return oauth2.hasAnyScopeMatching(scopesRegex);
    }
    
    public boolean denyOAuthClient(Authentication authentication) {
        OAuth2SecurityExpressionMethods oauth2 = new OAuth2SecurityExpressionMethods(authentication);
        return oauth2.denyOAuthClient();
    }
}
