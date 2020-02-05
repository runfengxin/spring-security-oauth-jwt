package com.service.hi.servicehi.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;
import org.springframework.security.web.access.AccessDeniedHandler;

@Configuration
@EnableResourceServer
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

    @Autowired
    private TokenStore tokenStore;

    @Autowired
    private MyAccessDeniedHandler accessDeniedHandler;

    @Autowired
    private MyTokenExceptionEntryPoint tokenExceptionEntryPoint;

    @Autowired
    private GoAuthenticationSuccessHandler goAuthenticationSuccessHandler;

    @Autowired
    private RedisConnectionFactory redisConnectionFactory;

//    @Bean
//    public RedisTokenStore tokenStore() {
//        RedisTokenStore tokenStore = new RedisTokenStore(redisConnectionFactory);
//        tokenStore.setPrefix("user-token:");
//        return tokenStore;
//    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//                .antMatchers("/order/**").authenticated(); // 配置order访问控制，必须认证后才可以访问

        http.csrf().disable();
        http.formLogin()
                .loginPage("/loginPage.html")// 自定义登录页
                .loginProcessingUrl("/user/login")// 自定义登录 action, 名字随便起
                .successHandler(goAuthenticationSuccessHandler);// 自定义登录成功处理类
//                .failureHandler(failureHandler);// 自定义登录失败处理类
        http
                .authorizeRequests()
                .antMatchers("/product/**","/registry/**", "/user/login/**",
                        "/logout/**","/v2/api-docs", "/swagger-resources/**",
                "/swagger-ui.html","/webjars/**","/loginPage.html").permitAll()
                .antMatchers("/**").authenticated()
//                .and().exceptionHandling().accessDeniedHandler(accessDeniedHandler)
        ;
    }

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.authenticationEntryPoint(tokenExceptionEntryPoint);
        resources.tokenStore(tokenStore);
    }
}
