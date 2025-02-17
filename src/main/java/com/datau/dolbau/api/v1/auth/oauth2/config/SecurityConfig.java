package com.datau.dolbau.api.v1.auth.oauth2.config;

import com.datau.dolbau.api.v1.auth.oauth2.apple.AppleOAuth2AuthorizationCodeGrantRequestEntityConverter;
import com.datau.dolbau.api.v1.auth.oauth2.service.OAuth2UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

@Slf4j
@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig {
    private final OAuth2UserService oAuth2UserService;
    private final AppleOAuth2AuthorizationCodeGrantRequestEntityConverter appleOAuth2AuthorizationCodeGrantRequestEntityConverter;
    String APPLE_REGISTRATION_ID = "apple";
    String KAKAO_REGISTRATION_ID = "kakao";

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.httpBasic().disable() // HTTP 기본 인증 비활성화
                .cors().disable()// CORS 비활성화
                .csrf().disable()// CSRF 보호 비활성화
                .formLogin().disable()// 폼 기반 로그인 비활성화
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)// 세션 생성 정책
                .and()
                .oauth2Login()
                .tokenEndpoint().accessTokenResponseClient(accessTokenResponseClient())// 액세스 토큰 응답 클라이언트
                .and()
                .userInfoEndpoint()
                .userService(oAuth2UserService) // 사용자 정보 엔드포인트
                .and()
                .successHandler(successHandler())// 성공 핸들러
                .failureHandler(failureHandler())// 실패 핸들러
        ;

        return httpSecurity.build();
    }

    @Bean
    public AuthenticationSuccessHandler successHandler() {
        return ((request, response, authentication) -> {
            OAuth2AuthenticationToken oAuth2AuthenticationToken = (OAuth2AuthenticationToken) authentication;
            String provider = oAuth2AuthenticationToken.getAuthorizedClientRegistrationId();
            log.info("Authorized provider :: @@@@@@@@@@@@@@@{}@@@@@@@@@@@@@@@@@@@@", provider);

            if (APPLE_REGISTRATION_ID.equals(provider)) {

            }
            if (KAKAO_REGISTRATION_ID.equals(provider)) {
                DefaultOAuth2User defaultOAuth2User = (DefaultOAuth2User) authentication.getPrincipal();
                String id = defaultOAuth2User.getAttributes().get("id").toString();
                String body = """
                    {"id":"%s"}
                    """.formatted(id);

                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.setCharacterEncoding(StandardCharsets.UTF_8.name());

                PrintWriter writer = response.getWriter();
                writer.println(body);
                writer.flush();
            }

            log.info("successHandler/request :: {}", request);
            log.info("successHandler/response :: {}", response);
            log.info("successHandler/authentication :: {}", authentication);
        });
    }

    public AuthenticationFailureHandler failureHandler() {
        return ((request, response, authentication) -> {
            log.info("failureHandler/request :: {}", request);
            log.info("failureHandler/response :: {}", response);
            log.info("failureHandler/authentication :: {}", authentication);
            authentication.printStackTrace();
        });
    }

    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
        DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
        accessTokenResponseClient.setRequestEntityConverter(appleOAuth2AuthorizationCodeGrantRequestEntityConverter);
        return accessTokenResponseClient;
    }
}
