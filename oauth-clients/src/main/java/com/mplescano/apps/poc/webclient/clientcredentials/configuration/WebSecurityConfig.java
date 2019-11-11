package com.mplescano.apps.poc.webclient.clientcredentials.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;

import reactor.core.publisher.Mono;

@Configuration
public class WebSecurityConfig {

    @Bean
    public ReactiveAuthenticationManager noopAuthenticationManager() {
        return new ReactiveAuthenticationManager() {
            @Override
            public Mono<Authentication> authenticate(Authentication authentication) {
                return Mono.empty();
            }
            
        };
    }
}