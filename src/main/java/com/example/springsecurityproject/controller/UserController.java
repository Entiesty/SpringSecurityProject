/**** 用户控制器 ****/
package com.example.springsecurityproject.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**** imports ****/
@RestController
@RequestMapping("/user")
public class UserController {
    @GetMapping("/message")
    public String message() {
        return "用户权限访问。";
    }
}