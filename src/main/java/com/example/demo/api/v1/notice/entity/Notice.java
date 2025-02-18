package com.example.demo.api.v1.notice.entity;

import lombok.*;

import java.time.LocalDateTime;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
public class Notice {
    private long noticeId;
    private String noticeTitle;
    private String noticeContent;
    private String deleteYn;
    LocalDateTime registerDtm;
    LocalDateTime updateDtm;
}
