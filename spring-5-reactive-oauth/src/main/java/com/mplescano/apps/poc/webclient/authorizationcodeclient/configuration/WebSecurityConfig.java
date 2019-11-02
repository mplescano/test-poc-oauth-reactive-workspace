package com.mplescano.apps.poc.webclient.authorizationcodeclient.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveAuthorizationCodeTokenResponseClient;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
public class WebSecurityConfig {
    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http.authorizeExchange()
            .anyExchange()
            .permitAll()
            .and()
            .oauth2Client();
        return http.build();
    }
    
    public ReactiveAuthenticationManager authenticationManager() {
        return new OAuth2AuthorizationCodeReactiveAuthenticationManager(new WebClientReactiveAuthorizationCodeTokenResponseClient());
    }
}