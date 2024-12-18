package com.PigeonSkyRace.Pigeon.service.impl;

import com.PigeonSkyRace.Pigeon.service.OAuth2Service;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class OAuth2ServiceImpl implements OAuth2Service {
    public Map<String, Object> getUserAttributes(OAuth2AuthenticationToken token) {
        return token.getPrincipal().getAttributes();
    }

    public String getUsername(OAuth2AuthenticationToken token) {
        return token.getPrincipal().getAttribute("preferred_username");
    }

    public String getEmail(OAuth2AuthenticationToken token) {
        return token.getPrincipal().getAttribute("email");
    }
}
