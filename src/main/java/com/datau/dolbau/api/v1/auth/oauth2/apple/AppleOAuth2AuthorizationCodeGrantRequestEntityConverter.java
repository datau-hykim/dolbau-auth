package com.datau.dolbau.api.v1.auth.oauth2.apple;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;

import java.util.Objects;

@Slf4j
@Component
public class AppleOAuth2AuthorizationCodeGrantRequestEntityConverter implements Converter<OAuth2AuthorizationCodeGrantRequest, RequestEntity<?>> {

    private final OAuth2AuthorizationCodeGrantRequestEntityConverter oAuth2AuthorizationCodeGrantRequestEntityConverter;
    private final AppleClientSecretGenerator appleClientSecretGenerator;

    private static final String APPLE_REGISTRATION_ID = "apple";
    private static final String CLIENT_SECRET_KEY = "client_secret";

    public AppleOAuth2AuthorizationCodeGrantRequestEntityConverter(AppleClientSecretGenerator appleClientSecretGenerator) {
        this.appleClientSecretGenerator = appleClientSecretGenerator;
        this.oAuth2AuthorizationCodeGrantRequestEntityConverter = new OAuth2AuthorizationCodeGrantRequestEntityConverter();
    }

    @Override
    public RequestEntity<?> convert(OAuth2AuthorizationCodeGrantRequest req) {
        RequestEntity<?> entity = oAuth2AuthorizationCodeGrantRequestEntityConverter.convert(req);

        String registrationId = req.getClientRegistration().getRegistrationId();

        if (APPLE_REGISTRATION_ID.equals(registrationId)) {
            String clientSecret = appleClientSecretGenerator.createClientSecret();

            log.info("client-secret/Apple: {}", clientSecret);

            updateParams(Objects.requireNonNull(entity), clientSecret);
        }

        return entity;
    }

    private void updateParams(RequestEntity<?> entity, String clientSecret) {
        MultiValueMap<String, String> params = (MultiValueMap<String, String>) entity.getBody();
        Objects.requireNonNull(params).set(CLIENT_SECRET_KEY, clientSecret);
    }
}