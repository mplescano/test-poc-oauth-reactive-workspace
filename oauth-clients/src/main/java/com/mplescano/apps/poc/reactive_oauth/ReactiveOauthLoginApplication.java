package com.mplescano.apps.poc.reactive_oauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.PropertySource;

import com.mplescano.apps.poc.commons.YamlPropertyLoaderFactory;

@PropertySource(value = "classpath:reactive-oauth-application.yml", factory = YamlPropertyLoaderFactory.class)
@SpringBootApplication
public class ReactiveOauthLoginApplication {

    public static void main(String[] args) {
        SpringApplication.run(ReactiveOauthLoginApplication.class, args);
    }
}