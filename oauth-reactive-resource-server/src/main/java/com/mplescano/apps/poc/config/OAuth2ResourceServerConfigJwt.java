package com.mplescano.apps.poc.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.SignerReactiveSimpleJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
public class OAuth2ResourceServerConfigJwt {

  @Bean
  SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http,
      JwtReactiveAuthenticationManager authenticationManager) {
    return http
          .authorizeExchange().anyExchange().authenticated()
          .and()
            .httpBasic().disable()
            .oauth2ResourceServer()
              .jwt()
                .authenticationManager(authenticationManager).and()
          .and()
            .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
            .exceptionHandling()
              .authenticationEntryPoint((exchange, exception) -> Mono.error(exception))
              .accessDeniedHandler((exchange, exception) -> Mono.error(exception))
          .and()
            .csrf().disable()
            .logout().disable()
          .build();
  }

  ReactiveJwtAuthenticationConverterAdapter jwtAuthenticationConverter() {
    return new ReactiveJwtAuthenticationConverterAdapter(new JwtAuthenticationConverter());
  }
  
  @Bean
  JwtReactiveAuthenticationManager authenticationManager(SignerReactiveSimpleJwtDecoder jwtDecoder) {
    JwtReactiveAuthenticationManager authenticationManager = new JwtReactiveAuthenticationManager(jwtDecoder);
    authenticationManager.setJwtAuthenticationConverter(jwtAuthenticationConverter());
    return authenticationManager;
  }
  
  @Bean
  SignerReactiveSimpleJwtDecoder jwtDecoder() {
    return new SignerReactiveSimpleJwtDecoder("123");
  }

}