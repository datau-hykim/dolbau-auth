package com.datau.dolbau.api.v1.auth.oauth2.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class TestController {
    @GetMapping("/")
    String test() {
        System.out.println("온겨?");
        return "test";
    }

}
