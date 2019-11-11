package com.mplescano.apps.poc.webclient.manualrequest;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.PropertySource;

import com.mplescano.apps.poc.commons.YamlPropertyLoaderFactory;

/**
 * 
 * Note: This app is configured to use the authorization service and the resource service located in Baeldung/spring-security-oauth repo
 * 
 * @author rozagerardo
 *
 */
@PropertySource(value = "classpath:webclient-manual-request-oauth-application.yml", factory = YamlPropertyLoaderFactory.class)
@SpringBootApplication
public class ManualRequestApplication {

    public static void main(String[] args) {
        SpringApplication.run(ManualRequestApplication.class, args);
    }
}