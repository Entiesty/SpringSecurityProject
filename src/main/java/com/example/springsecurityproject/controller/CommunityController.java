/**** 公共控制器 ****/
package com.example.springsecurityproject.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**** imports ****/
@RestController
@RequestMapping("/community")
public class CommunityController {
    @GetMapping("/message")
    public String message() {
        return "可匿名访问";
    }
}