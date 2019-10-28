/*
 * Copyright 2006-2011 the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.oauth2.provider.expression;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * @author Dave Syer
 * @author Radek Ostrowski
 * 
 */
public abstract class OAuth2ExpressionUtils {

    final static String AUD = "aud";

    final static String CLIENT_ID = "client_id";

    final static String EXP = "exp";

    final static String JTI = "jti";
    
    final static String GRANT_TYPE = "grant_type";

    final static String ATI = "ati";

    public static String SCOPE = "scope";

    final static String AUTHORITIES = "authorities";
    
    private static String scopeAttribute = SCOPE;

	public static boolean clientHasAnyRole(Authentication authentication, String... roles) {
		Collection<? extends GrantedAuthority> clientAuthorities = authentication.getAuthorities();
		if (clientAuthorities != null) {
			Set<String> roleSet = AuthorityUtils.authorityListToSet(clientAuthorities);
			for (String role : roles) {
				if (roleSet.contains(role)) {
					return true;
				}
			}
		}
	
		return false;
	}

	public static boolean isOAuth(Authentication authentication) {
		
		if (authentication instanceof JwtAuthenticationToken) {
			return true;
		}
	
		return false;
	}

	public static boolean isOAuthClientAuth(Authentication authentication) {
		
		if (authentication instanceof JwtAuthenticationToken) {
			return authentication.isAuthenticated();
		}
	
		return false;
	}

	public static boolean isOAuthUserAuth(Authentication authentication) {
		return false;
	}

    private static Set<String> extractScope(Map<String, ?> map) {
        Set<String> scope = Collections.emptySet();
        if (map.containsKey(scopeAttribute)) {
            Object scopeObj = map.get(scopeAttribute);
            if (String.class.isInstance(scopeObj)) {
                scope = new LinkedHashSet<String>(Arrays.asList(String.class.cast(scopeObj).split(" ")));
            } else if (Collection.class.isAssignableFrom(scopeObj.getClass())) {
                @SuppressWarnings("unchecked")
                Collection<String> scopeColl = (Collection<String>) scopeObj;
                scope = new LinkedHashSet<String>(scopeColl);   // Preserve ordering
            }
        }
        return scope;
    }
	
	public static boolean hasAnyScope(Authentication authentication, String[] scopes) {

		if (authentication instanceof JwtAuthenticationToken) {
		    Jwt clientAuthentication = ((JwtAuthenticationToken) authentication).getToken();
			Collection<String> assigned = extractScope(clientAuthentication.getClaims());
			if (assigned != null) {
				for (String scope : scopes) {
					if (assigned.contains(scope)) {
						return true;
					}
				}
			}
		}
	
		return false;
	}

	public static boolean hasAnyScopeMatching(Authentication authentication, String[] scopesRegex) {

		if (authentication instanceof JwtAuthenticationToken) {
		    Jwt clientAuthentication = ((JwtAuthenticationToken) authentication).getToken();
			for (String scope : extractScope(clientAuthentication.getClaims())) {
				for (String regex : scopesRegex) {
					if (scope.matches(regex)) {
						return true;
					}
				}
			}
		}

		return false;
	}

}