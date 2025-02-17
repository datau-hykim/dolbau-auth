package com.datau.dolbau.api.v1.auth.oauth2.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Slf4j
@Controller
@RequestMapping("/login")
public class OAuthLoginController {
    //kakao
    @GetMapping("")
    public String kakaoLogin() {
        return "login.html";
    }
}



