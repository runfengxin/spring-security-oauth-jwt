package com.service.auth.serviceauth.config;

import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
public class AuthencationSuccessListener implements ApplicationListener<AuthenticationSuccessEvent> {
    @Override
    public void onApplicationEvent(AuthenticationSuccessEvent authenticationSuccessEvent) {
        //用户通过输入用户名和密码登录成功
        System.out.println("---AuthenticationSuccessEvent---");
    }
}
