package com.mplescano.apps.poc.reactive_oauth;

import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.DelegatingReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.util.ClassUtils;

@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain configure(ServerHttpSecurity http, ReactiveAuthenticationManager defaultAuthenticationManager) throws Exception {
        return http.authorizeExchange()
            .pathMatchers("/about").permitAll()
            .anyExchange().authenticated()
            .and().oauth2Login().authenticationManager(defaultAuthenticationManager)
            .and().build();
    }
    
    @Bean
    public ReactiveAuthenticationManager defaultAuthenticationManager() {
        WebClientReactiveAuthorizationCodeTokenResponseClient client = new WebClientReactiveAuthorizationCodeTokenResponseClient();
        ReactiveAuthenticationManager result = new OAuth2LoginReactiveAuthenticationManager(client, new DefaultReactiveOAuth2UserService());

        boolean oidcAuthenticationProviderEnabled = ClassUtils.isPresent(
                "org.springframework.security.oauth2.jwt.JwtDecoder", this.getClass().getClassLoader());
        if (oidcAuthenticationProviderEnabled) {
            OidcAuthorizationCodeReactiveAuthenticationManager oidc = new OidcAuthorizationCodeReactiveAuthenticationManager(client, new OidcReactiveOAuth2UserService());
            result = new DelegatingReactiveAuthenticationManager(oidc, result);
        }
        return result;
    }
}