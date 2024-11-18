package com.example.springsecurityproject.po;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@TableName("t_user")
public class UserPo {
    @TableId(type = IdType.AUTO)
    private Long id;
    @TableField("user_name")
    private String userName;
    @TableField("pwd")
    private String password;
    private Integer available;
    private String note;
    @TableField(exist = false)
    private List<RolePo> rolePoList;
}
