package com.example.springsecurityproject.security;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.example.springsecurityproject.po.RolePo;
import com.example.springsecurityproject.po.UserPo;
import com.example.springsecurityproject.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.net.http.HttpRequest;
import java.util.*;

@Configuration
public class WebSecurityCustomConfig {
/*    @Bean
    public PasswordEncoder initPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }*/

/*    @Bean
    public PasswordEncoder initPasswordEncoder(@Value("${user.password.encoder.secret}") String secret) {
        return new Pbkdf2PasswordEncoder(secret, 16, 310000,
                Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA512);
    }*/

/*    @Bean
    public UserDetailsService initInMemoryUserDetailsService(@Autowired PasswordEncoder pwdEncoder) {
        GrantedAuthority userAuth = () -> "ROLE_USER";
        GrantedAuthority adminAuth = () -> "ROLE_ADMIN";

        List<UserDetails> userList = List.of(
                new User("user1", pwdEncoder.encode("123456"), List.of(userAuth)),
                new User("admin", pwdEncoder.encode("abcdefg"), List.of(userAuth, adminAuth))
        );

        return new InMemoryUserDetailsManager(userList);
    }*/

/*    @Bean
    public UserDetailsService initJdbcUserDetailsService(@Autowired JdbcTemplate jdbcTemplate) {
        // 使用用户名称查询密码
        String userSql = """
        select user_name, pwd, available
        from t_user where user_name = ?
        """;
        // 使用用户名称查询权限信息
        var authsql = """
        select u.user_name, r.role_name
        from t_user u, t_user_role ur, t_role r
        where u.id = ur.user_id and r.id = ur.role_id
        and u.user_name = ?
        """ ;
        // 创建数据库用户详情管理
        var userDetailsService = new JdbcUserDetailsManager(); // ①
        // 设置查询用户信息的SQL
        userDetailsService.setUsersByUsernameQuery(userSql); // ②
        // 设置查询角色和权限的SQL
        userDetailsService.setAuthoritiesByUsernameQuery(authsql); // ③
        // 设置JdbcTemplate
        userDetailsService.setJdbcTemplate(jdbcTemplate);
        return userDetailsService;
    }*/

/*    @Bean
    public UserDetailsService initUserDetailsService(@Autowired UserService userService) {
        return username -> {
            QueryWrapper<UserPo> userPoQueryWrapper = new QueryWrapper<>();
            userPoQueryWrapper.eq("user_name", username);
            UserPo userPo = userService.getOne(userPoQueryWrapper);

            List<GrantedAuthority> authorityList = new ArrayList<>();
            for (RolePo rolePo : userPo.getRolePoList()) {
                GrantedAuthority ga = rolePo::getRoleName;
                authorityList.add(ga);
            }

            return (UserDetails) new User(userPo.getUserName(), userPo.getPassword(), authorityList);
        };
    }*/

/*    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                // ######## 权限配置 ########
                .authorizeHttpRequests(auth -> auth
                        // "/user/**" 需要 ROLE_USER 或 ROLE_ADMIN
                        .requestMatchers("/user/**").hasAnyRole("USER", "ADMIN")
                        // "/admin/**" 需要 ROLE_ADMIN
                        .requestMatchers("/admin/**").hasAuthority("ADMIN")
                        // 其他请求允许所有访问
                        .anyRequest().permitAll()
                )

                // ######## 匿名访问 ########
                .anonymous(Customizer.withDefaults())

                // ######## 登录配置 ########
                // 启用默认登录页面
                .formLogin(Customizer.withDefaults())

                // ######## HTTP 基础认证 ########
                // 启用 HTTP Basic 认证
                .httpBasic(Customizer.withDefaults())

                // ######## 构建 Filter Chain ########
                .build();
    }*/


/*    public static AuthorizationManager<RequestAuthorizationContext> authMgr(String... roleNames) {
        // 输入参数校验
        if (roleNames == null) {
            throw new IllegalArgumentException("角色列表不能为 null");
        }

        if (roleNames.length == 0) {
            throw new IllegalArgumentException("角色列表不能为空");
        }

        // 转换角色数组为不可变 Set 提高匹配效率
        Set<String> roleNameSet = Set.of(roleNames);

        // 返回自定义 AuthorizationManager
        return (authSupplier, reqAuthContext) -> {
            // 获取当前用户的权限
            Collection<? extends GrantedAuthority> authorities = authSupplier.get().getAuthorities();

            // 遍历权限集合，检查是否拥有目标角色
            boolean hasRole = authorities.stream()
                    .map(GrantedAuthority::getAuthority) // 提取权限名称
                    .filter(roleName -> roleName.startsWith("ROLE_")) // 确保匹配的是角色权限
                    .anyMatch(roleNameSet::contains); // 检查是否在目标角色集合中

            // 返回授权决策
            return new AuthorizationDecision(hasRole);
        };
    }*/

/*    @Bean
    public SecurityFilterChain init(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/user/**").access(authMgr("ROLE_USER", "ROLE_ADMIN"))
                .requestMatchers("/admin/**").access(authMgr("ROLE_ADMIN")))
                .formLogin(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults())
                .build();
    }*/

    @Bean
    public PasswordEncoder passwordEncoder(@Value("${user.password.encoder.secret}") String secret) {
        return new Pbkdf2PasswordEncoder(secret, 16, 310000,
                Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA512);
    }

    @Bean
    public UserDetailsService userDetailsService(@Autowired UserService userService) {
        return username -> {
            // 查询用户
            QueryWrapper<UserPo> wrapper = new QueryWrapper<>();
            wrapper.eq("user_name", username);
            UserPo userPo = userService.getOne(wrapper);

            // 检查用户是否存在
            if (userPo == null) {
                throw new UsernameNotFoundException("用户名或密码错误");
            }

            // 获取用户角色列表并处理空值
            List<RolePo> roles = userPo.getRolePoList();
            if (roles == null) {
                roles = Collections.emptyList();
            }

            // 构建权限列表
            List<GrantedAuthority> authorities = roles.stream()
                    .map(role -> (GrantedAuthority) role::getRoleName)
                    .toList();

            // 构建 User 对象并返回
            return new User(userPo.getUserName(), userPo.getPassword(), authorities);
        };
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(auth -> auth
                        .requestMatchers("/user/**").access(authMgr("ROLE_USER", "ROLE_ADMIN"))
                        .requestMatchers("/admin/**").access(authMgr("ROLE_ADMIN"))
                        .anyRequest().permitAll()
                )
                .formLogin(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults())
                .build();
    }

    public static AuthorizationManager<RequestAuthorizationContext> authMgr(String... roles) {
        if (roles == null || roles.length == 0) {
            throw new IllegalArgumentException("角色列表不能为空");
        }

        Set<String> roleSet = Set.of(roles);

        return (authSupplier, reqAuthContext) -> {
            Collection<? extends GrantedAuthority> authorities = authSupplier.get().getAuthorities();
            boolean hasRole = authorities.stream()
                    .map(GrantedAuthority::getAuthority)
                    .filter(role -> role.startsWith("ROLE_"))
                    .anyMatch(roleSet::contains);

            return new AuthorizationDecision(hasRole);
        };
    }
}
