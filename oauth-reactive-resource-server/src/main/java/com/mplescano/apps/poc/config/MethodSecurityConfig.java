package com.mplescano.apps.poc.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;

@Configuration
@EnableReactiveMethodSecurity
public class MethodSecurityConfig {

    @Bean
    FacadeOauth2Handler oauth2Handler() {
        return new FacadeOauth2Handler();
    }
    
}