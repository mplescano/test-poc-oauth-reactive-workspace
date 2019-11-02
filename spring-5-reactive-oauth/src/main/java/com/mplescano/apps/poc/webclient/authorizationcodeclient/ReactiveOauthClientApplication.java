package com.mplescano.apps.poc.webclient.authorizationcodeclient;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.PropertySource;

import com.mplescano.apps.poc.commons.YamlPropertyLoaderFactory;

/**
 * 
 * Note: This app is configured to use the authorization service and the resource service located in Baeldung/spring-security-oauth repo
 * 
 * As we usually do with other well-known auth providers (github/facebook/...) we have to log-in using user credentials (john/123) and client configurations handled by the auth server
 * 
 * @author rozagerardo
 *
 */
@PropertySource(value = "classpath:webclient-auth-code-client-application.yml", factory = YamlPropertyLoaderFactory.class)
@SpringBootApplication
public class ReactiveOauthClientApplication {

    public static void main(String[] args) {
        SpringApplication.run(ReactiveOauthClientApplication.class, args);
    }

}