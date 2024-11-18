package com.example.springsecurityproject.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.example.springsecurityproject.mapper.UserMapper;
import com.example.springsecurityproject.po.UserPo;
import com.example.springsecurityproject.service.UserService;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, UserPo> implements UserService {
}
