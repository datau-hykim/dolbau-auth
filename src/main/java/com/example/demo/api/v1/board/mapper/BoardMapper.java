package com.example.demo.api.v1.board.mapper;

import com.example.demo.api.v1.board.entity.Board;
import com.example.demo.common.entity.Pagination;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface BoardMapper {
    Board selectBoardById(Board board);
    List<Board> selectBoardList(Pagination param);
    Integer insertBoard(Board board);
    Integer updateBoard(Board board);
}
