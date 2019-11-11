package com.mplescano.apps.poc.webclient.manualrequest.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class WebClientConfig {

    @Bean
    public WebClient configureWebClient() {
        return WebClient.builder()
            .build();
    };

}