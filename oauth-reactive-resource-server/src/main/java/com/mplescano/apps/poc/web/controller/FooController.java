package com.mplescano.apps.poc.web.controller;

import static org.apache.commons.lang3.RandomStringUtils.randomAlphabetic;
import static org.apache.commons.lang3.RandomStringUtils.randomNumeric;

import com.mplescano.apps.poc.web.dto.Foo;

import reactor.core.publisher.Mono;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

@Controller
public class FooController {

  public FooController() {
    super();
  }

  // API - read
  @PreAuthorize("@oauth2Handler.hasScope(authentication, 'foo') and @oauth2Handler.hasScope(authentication, 'read')")
  @RequestMapping(method = RequestMethod.GET, value = "/foos/{id}")
  @ResponseBody
  public Mono<Foo> findById(@PathVariable final long id) {
    return Mono.just(new Foo(Long.parseLong(randomNumeric(2)), randomAlphabetic(4)));
  }

  // API - write
  @PreAuthorize("@oauth2Handler.hasScope(authentication, 'foo') and @oauth2Handler.hasScope(authentication, 'write')")
  @RequestMapping(method = RequestMethod.POST, value = "/foos")
  @ResponseStatus(HttpStatus.CREATED)
  @ResponseBody
  public Mono<Foo> create(@RequestBody final Foo foo) {
    foo.setId(Long.parseLong(randomNumeric(2)));
    return Mono.just(foo);
  }

}