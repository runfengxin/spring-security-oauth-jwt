package com.service.auth.serviceauth.config.sms;

import com.service.auth.serviceauth.dto.UserServiceDetail;
import org.apache.commons.lang.StringUtils;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

import java.util.LinkedHashMap;
import java.util.Map;

public class SMSCodeTokenGranter extends AbstractTokenGranter {

    private UserServiceDetail userServiceDetail;

    private static final String GRANT_TYPE = "sms_code";

    public SMSCodeTokenGranter(AuthorizationServerTokenServices tokenServices,
                                    ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory,
                               UserServiceDetail userServiceDetail) {
        super(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE);
        this.userServiceDetail=userServiceDetail;
    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client,
                                                           TokenRequest tokenRequest) {

        Map<String, String> parameters = new LinkedHashMap<String, String>(tokenRequest.getRequestParameters());
        String userMobileNo = parameters.get("username");  //客户端提交的用户名
        String smscode = parameters.get("smscode");  //客户端提交的验证码

        // 从库里查用户
        UserDetails user = userServiceDetail.loadUserByUsername(userMobileNo);
        if(user == null) {
            System.out.println("用户不存在");
        }

        //验证用户状态(是否警用等),代码略

        // 验证验证码
        String smsCodeCached = "1234";
        if(StringUtils.isBlank(smsCodeCached)) {
            System.out.println("用户没有发送验证码");
        }
        if(!smscode.equals(smsCodeCached)) {
            System.out.println("验证码不正确");
        }else {
            //验证通过后从缓存中移除验证码,代码略
        }


        Authentication userAuth = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
        // 关于user.getAuthorities(): 我们的自定义用户实体是实现了
        // org.springframework.security.core.userdetails.UserDetails 接口的, 所以有 user.getAuthorities()
        // 当然该参数传null也行
        ((AbstractAuthenticationToken) userAuth).setDetails(parameters);

        OAuth2Request storedOAuth2Request = getRequestFactory().createOAuth2Request(client, tokenRequest);
        return new OAuth2Authentication(storedOAuth2Request, userAuth);
    }
}
