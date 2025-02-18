package com.example.demo.api.v1.notice.dto;

import com.datau.dolbau.boilerplate.util.DateUtil;
import com.example.demo.api.v1.notice.entity.Notice;
import lombok.*;

public class NoticeDto {
    public record Response(long noticeId, String noticeTitle, String noticeContent, String deleteYn, long registerDtm, long updateDtm) {
        public static Response of(Notice notice) {
            return new Response(
                    notice.getNoticeId(),
                    notice.getNoticeTitle(),
                    notice.getNoticeContent(),
                    notice.getDeleteYn(),
                    DateUtil.toUnix(notice.getRegisterDtm()),
                    DateUtil.toUnix(notice.getUpdateDtm())
            );
        }
    }

    public record Request(String noticeTitle, String noticeContent) {
        public Notice toEntity(){
            return Notice.builder()
                    .noticeTitle(this.noticeTitle)
                    .noticeContent(this.noticeContent)
                    .build();
        }
    }
}
