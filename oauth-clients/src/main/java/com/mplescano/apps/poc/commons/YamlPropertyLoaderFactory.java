package com.mplescano.apps.poc.commons;

import java.io.IOException;

import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.CompositePropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.support.DefaultPropertySourceFactory;
import org.springframework.core.io.support.EncodedResource;

public class YamlPropertyLoaderFactory extends DefaultPropertySourceFactory {

  @Override
  public PropertySource<?> createPropertySource(String name, EncodedResource resource) throws IOException {
    if (resource == null) {
      return super.createPropertySource(name, resource);
    }
    String sourceName = name != null ? name : resource.getResource().getFilename();
    CompositePropertySource propertySource = new CompositePropertySource(sourceName);
    new YamlPropertySourceLoader().load(resource.getResource().getFilename(), resource.getResource()).stream()
        .forEach(propertySource::addPropertySource);

    return propertySource;
  }

}
