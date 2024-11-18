/**** 管理员控制器 ****/
package com.example.springsecurityproject.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**** imports ****/
@RestController
@RequestMapping("/admin")
public class AdminController {
    @GetMapping("/message")
    public String message() {
        return "管理员权限";
    }
}