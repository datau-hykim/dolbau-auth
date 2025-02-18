package com.example.demo.api.v1.notice.service;

import com.datau.dolbau.boilerplate.entity.page.Page;
import com.datau.dolbau.boilerplate.entity.page.Pagination;
import com.datau.dolbau.boilerplate.entity.page.RequestPage;
import com.example.demo.api.v1.notice.dto.NoticeDto;
import com.example.demo.api.v1.notice.entity.Notice;
import com.example.demo.api.v1.notice.mapper.NoticeMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class NoticeService {
    private final NoticeMapper noticeMapper;

    public Page<NoticeDto.Response> getNoticeList(NoticeDto.Request request, Pagination pagination) {
        RequestPage<Notice> requestPage = RequestPage.<Notice>builder()
                .param(request.toEntity())
                .pagination(pagination)
                .build();

        int noticeCnt = this.noticeMapper.selectNoticeCount(requestPage);
        pagination.setTotal(noticeCnt);

        List<NoticeDto.Response> noticeList = this.noticeMapper.selectNoticeList(requestPage).stream()
                .map(NoticeDto.Response::of)
                .toList();;

        return Page.<NoticeDto.Response>builder()
                .list(noticeList)
                .pagination(pagination)
                .build();
    }
}
