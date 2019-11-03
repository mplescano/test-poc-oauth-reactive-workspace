package com.mplescano.apps.poc.webclient.clientcredentials;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.PropertySource;
import org.springframework.scheduling.annotation.EnableScheduling;

import com.mplescano.apps.poc.commons.YamlPropertyLoaderFactory;

/**
 * 
 * Note: This app is configured to use the authorization service and the resource service located in Baeldung/spring-security-oauth repo
 * 
 * @author rozagerardo
 *
 */
@PropertySource(value = "classpath:webclient-client-credentials-oauth-application.yml", factory = YamlPropertyLoaderFactory.class)
@EnableScheduling
@SpringBootApplication
public class ClientCredentialsOauthApplication {

    public static void main(String[] args) {
        SpringApplication.run(ClientCredentialsOauthApplication.class, args);
    }

}