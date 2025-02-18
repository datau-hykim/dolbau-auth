package com.example.demo.api.v1.notice.controller;

import com.datau.dolbau.boilerplate.auth.JwtHelper;
import com.datau.dolbau.boilerplate.auth.JwtPayload;
import com.datau.dolbau.boilerplate.constant.error.ErrorCodeImpl;
import com.datau.dolbau.boilerplate.entity.page.Page;
import com.datau.dolbau.boilerplate.entity.page.Pagination;
import com.datau.dolbau.boilerplate.exception.BizException;
import com.example.demo.api.v1.notice.dto.NoticeDto;
import com.example.demo.api.v1.notice.service.NoticeService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/v1/notices")
public class NoticeController {
    private final NoticeService noticeService;

    @GetMapping("")
    public Page<NoticeDto.Response> getNoticeList(@ModelAttribute NoticeDto.Request request, Pagination pagination){
        return this.noticeService.getNoticeList(request, pagination);
    }
}
