package com.okta.sample.idx.service;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

@Service
public class ClaimsService {

    private static final String UNPARSEABLE_KEY = "(token)";

    public Map<String, Object> decode(String token) {
        if (token == null) {
            return Map.of();
        }
        try {
            JWTClaimsSet claims = JWTParser.parse(token).getJWTClaimsSet();
            return new TreeMap<>(claims.getClaims());
        } catch (ParseException e) {
            Map<String, Object> fallback = new LinkedHashMap<>();
            fallback.put(UNPARSEABLE_KEY, "Not a parseable JWT (opaque token) - raw value shown below");
            return fallback;
        }
    }
}
