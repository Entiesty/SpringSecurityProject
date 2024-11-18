package com.example.springsecurityproject.po;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@TableName("t_user_role")
public class RolePo {
    @TableId(type = IdType.AUTO)
    private Long id;
    @TableField("role_name")
    private String roleName;
    private String note;
}
