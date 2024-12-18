package com.PigeonSkyRace.Pigeon.controller;

import com.PigeonSkyRace.Pigeon.service.OAuth2Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.security.Principal;

@RestController
@RequestMapping("/oauth")
public class OAuth2Controller {

    @Autowired
    private OAuth2Service oAuth2Service;

    @GetMapping("/public/hello")
    public String publicHello() {
        return "This is a public endpoint. No authentication required!";
    }

    @GetMapping("/secured/userinfo")
    public Map<String, Object> userInfo(Principal principal) {
        if (principal instanceof OAuth2AuthenticationToken) {
            OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) principal;
            return oAuth2Service.getUserAttributes(token);
        }
        throw new IllegalStateException("User is not authenticated with OAuth2.");
    }

    @GetMapping("/secured/username")
    public String username(Principal principal) {
        if (principal instanceof OAuth2AuthenticationToken) {
            OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) principal;
            return "Hello, " + oAuth2Service.getUsername(token);
        } else if (principal instanceof org.springframework.security.authentication.UsernamePasswordAuthenticationToken) {
            return "Hello, authenticated user with ID: " + principal.getName();
        }
        return "Unknown user principal.";
    }
}
