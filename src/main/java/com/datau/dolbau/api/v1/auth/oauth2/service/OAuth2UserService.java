package com.datau.dolbau.api.v1.auth.oauth2.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.RequestEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.util.*;

@Slf4j
@RequiredArgsConstructor
@Service
public class OAuth2UserService extends DefaultOAuth2UserService {

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        Map<String, Object> userAttributes = new HashMap<>();

        List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
        String userNameAttributeKey = "";
        OAuth2AccessToken accessToken = userRequest.getAccessToken();

        log.info("AccessToken: {}", accessToken.getTokenValue());

        String APPLE_REGISTRATION_ID = "apple";
        String KAKAO_REGISTRATION_ID = "kakao";

        //************Apple*************
        if (APPLE_REGISTRATION_ID.equals(registrationId)) {
            Map<String, Object> attributes;
            String idToken = userRequest.getAdditionalParameters().get("id_token").toString();
            attributes = this.decodeAppleJwtTokenPayload(idToken);
            attributes.put("id_token", idToken);

            userAttributes.put("resultcode", "00");
            userAttributes.put("message", "success");
            userAttributes.put("response", attributes);

            userNameAttributeKey = "response";


            Iterator<String> paramKeyLsit = userRequest.getAdditionalParameters().keySet().iterator();
            while (paramKeyLsit.hasNext()) {
                String key = paramKeyLsit.next();
                Object value = userRequest.getAdditionalParameters().get(key);
                log.info("\t key :: {}, value: {}", key, value);
            }
            Iterator<String> attKeyLsit = attributes.keySet().iterator();
            while (attKeyLsit.hasNext()) {
                String key = attKeyLsit.next();
                Object value = attributes.get(key);
                log.info("\t key :: {}, value: {}", key, value);
            }
        }
        //************KaKao*************
        if (KAKAO_REGISTRATION_ID.equals(registrationId)) {
            OAuth2User oAuth2User = super.loadUser(userRequest);
            userAttributes.putAll(oAuth2User.getAttributes());

            userNameAttributeKey = userRequest.getClientRegistration()
                    .getProviderDetails()
                    .getUserInfoEndpoint()
                    .getUserNameAttributeName();
        }

        return new DefaultOAuth2User(authorities, userAttributes, userNameAttributeKey);
    }

    private Map<String, Object> decodeAppleJwtTokenPayload(String jwtToken) {
        Map<String, Object> jwtClaims = new HashMap<>();
        try {
            String[] parts = jwtToken.split("\\.");
            Base64.Decoder decoder = Base64.getUrlDecoder();

            byte[] decodedBytes = decoder.decode(parts[1].getBytes(StandardCharsets.UTF_8));
            String decodedString = new String(decodedBytes, StandardCharsets.UTF_8);
            ObjectMapper mapper = new ObjectMapper();

            Map<String, Object> map = mapper.readValue(decodedString, Map.class);
            jwtClaims.putAll(map);

        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
        return jwtClaims;
    }

}

