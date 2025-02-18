package com.example.demo.api.v1.notice.mapper;

import com.datau.dolbau.boilerplate.entity.page.RequestPage;
import com.example.demo.api.v1.notice.entity.Notice;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface NoticeMapper {
    List<Notice> selectNoticeList(RequestPage<Notice> requestPage);

    int selectNoticeCount(RequestPage<Notice> requestPage);
}
