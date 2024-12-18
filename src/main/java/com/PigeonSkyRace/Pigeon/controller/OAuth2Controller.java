package com.PigeonSkyRace.Pigeon.controller;

import com.PigeonSkyRace.Pigeon.service.OAuth2Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

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
    public Map<String, Object> userInfo(OAuth2AuthenticationToken token) {
        return oAuth2Service.getUserAttributes(token);
    }

    @GetMapping("/secured/username")
    public String username(OAuth2AuthenticationToken token) {
        return "Hello, " + oAuth2Service.getUsername(token);
    }
}
