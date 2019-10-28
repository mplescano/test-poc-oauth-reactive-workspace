package com.mplescano.apps.poc.web.controller;

import java.util.Map;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class UserController {

  @PreAuthorize("@oauth2Handler.hasScope(authentication, 'read')")
  @RequestMapping(method = RequestMethod.GET, value = "/users/extra")
  @ResponseBody
  public Map<String, Object> getExtraInfo(Authentication auth) {
    Jwt oauthDetails = (Jwt) auth.getPrincipal();
    Map<String, Object> details = (Map<String, Object>) oauthDetails.getClaims();
    System.out.println("User organization is " + details.get("organization"));
    return details;
  }
}