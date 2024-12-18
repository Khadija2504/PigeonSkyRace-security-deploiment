package com.PigeonSkyRace.Pigeon.service;

import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;

import java.util.Map;

public interface OAuth2Service {
    String getEmail(OAuth2AuthenticationToken token);
    String getUsername(OAuth2AuthenticationToken token);
    Map<String, Object> getUserAttributes(OAuth2AuthenticationToken token);
}
