package com.nowcoder.community.controller;

import com.nowcoder.community.entity.DiscussPost;
import com.nowcoder.community.entity.Page;
import com.nowcoder.community.service.ElasticsearchService;
import com.nowcoder.community.service.LikeService;
import com.nowcoder.community.service.UserService;
import com.nowcoder.community.util.CommunityConstant;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
public class SearchController implements CommunityConstant {
    // 搜索
    @Autowired
    private ElasticsearchService elasticsearchService;

    // 搜到后展示作者和点赞数
    @Autowired
    private LikeService likeService;

    @Autowired
    private UserService userService;

    // 路径格式：/search?keyword=xxx
    @RequestMapping(path = "/search", method = RequestMethod.GET)
    public String search(String keyword, Page page, Model model){
        // 搜索帖子
        // page的current从1开始但是本方法要求从0开始
        org.springframework.data.domain.Page<DiscussPost> searchResult =
                elasticsearchService.searchDiscussPost(keyword, page.getCurrent() - 1, page.getLimit());

        List<Map<String, Object>> discussPosts = new ArrayList<>();
        if(searchResult != null){
            for(DiscussPost post : searchResult){
                Map<String, Object> map = new HashMap<>();

                map.put("post", post);
                map.put("user", userService.findUserById(post.getUserId()));  // 作者
                map.put("likeCount", likeService.findEntityLikeCount(ENTITY_TYPE_POST, post.getId()));  // 赞数

                discussPosts.add(map);
            }
        }
        model.addAttribute("discussPosts", discussPosts);
        model.addAttribute("keyword", keyword);

        page.setPath("/search?keyword=" + keyword);
        page.setRows(searchResult == null ? 0 : (int)searchResult.getTotalElements());

        return "/site/search";
    }
}