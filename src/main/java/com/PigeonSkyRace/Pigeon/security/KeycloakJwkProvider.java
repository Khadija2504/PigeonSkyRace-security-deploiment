package com.PigeonSkyRace.Pigeon.security;

import com.auth0.jwt.interfaces.RSAKeyProvider;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.math.BigInteger;
import java.net.URL;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

public class KeycloakJwkProvider implements RSAKeyProvider {

    private final String jwkUrl;

    public KeycloakJwkProvider(String jwkUrl) {
        this.jwkUrl = jwkUrl;
    }

    @Override
    public RSAPublicKey getPublicKeyById(String keyId) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode jwks = mapper.readTree(new URL(jwkUrl));
            JsonNode keys = jwks.get("keys");

            // Iterate over JWKS keys to find the one with the matching kid
            for (JsonNode key : keys) {
                if (key.get("kid").asText().equals(keyId)) {
                    String n = key.get("n").asText(); // Modulus
                    String e = key.get("e").asText(); // Exponent

                    // Decode the modulus and exponent
                    BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(n));
                    BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(e));

                    // Build the RSA public key
                    RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, exponent);
                    return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);
                }
            }
            throw new RuntimeException("Key ID not found: " + keyId);
        } catch (Exception e) {
            throw new RuntimeException("Failed to fetch public key: " + e.getMessage(), e);
        }
    }

    @Override
    public RSAPrivateKey getPrivateKey() {
        return null; // Not required for verifying JWTs
    }

    @Override
    public String getPrivateKeyId() {
        return null; // Not required for verifying JWTs
    }
}
