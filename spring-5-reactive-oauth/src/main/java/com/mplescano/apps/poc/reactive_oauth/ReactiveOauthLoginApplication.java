package com.mplescano.apps.poc.reactive_oauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.web.reactive.function.client.WebClient;

import com.mplescano.apps.poc.commons.YamlPropertyLoaderFactory;

@PropertySource(value = "classpath:reactive-oauth-application.yml", factory = YamlPropertyLoaderFactory.class)
@SpringBootApplication
public class ReactiveOauthLoginApplication {

    public static void main(String[] args) {
        SpringApplication.run(ReactiveOauthLoginApplication.class, args);
    }

    @Bean
    public WebClient webClient(ReactiveClientRegistrationRepository clientRegistrationRepo, ServerOAuth2AuthorizedClientRepository authorizedClientRepo) {
        ServerOAuth2AuthorizedClientExchangeFilterFunction filter = new ServerOAuth2AuthorizedClientExchangeFilterFunction(clientRegistrationRepo, authorizedClientRepo);
        return WebClient.builder()
            .filter(filter)
            .build();
    }
}