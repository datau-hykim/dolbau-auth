package com.example.demo.api.v1.notice.controller;

import com.datau.dolbau.boilerplate.auth.JwtHelper;
import com.datau.dolbau.boilerplate.auth.JwtPayload;
import com.datau.dolbau.boilerplate.constant.error.ErrorCodeImpl;
import com.datau.dolbau.boilerplate.exception.BizException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/v1/test")
public class DemoController {
    private final JwtHelper JwtHelper;

    @GetMapping("")
    public void test(@PathVariable Long noticeId){
        throw new BizException(ErrorCodeImpl.INTERNAL_SERVER_ERROR);
    }

    @PostMapping("token")
    public String createToken(){
        log.info("Create Token");
        String newRefreshToken = this.JwtHelper.generateRefreshToken(JwtPayload.builder().memberId(1L).build());

        log.info("newRefreshToken :: {}", newRefreshToken);

        return newRefreshToken;
    }
}
