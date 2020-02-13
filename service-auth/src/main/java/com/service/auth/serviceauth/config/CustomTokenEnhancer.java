package com.service.auth.serviceauth.config;

import com.service.auth.serviceauth.entity.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import java.util.HashMap;
import java.util.Map;

/**
 * 自定义token参数
 */
@Slf4j
public class CustomTokenEnhancer implements TokenEnhancer {
    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        User user = null;
        String str = null;
        if (authentication.getPrincipal() instanceof User) {
            user = (User) authentication.getPrincipal();
        } else if(authentication.getPrincipal() instanceof String) {
            str = (String) authentication.getPrincipal();
        }
        final Map<String, Object> additionalInfo = new HashMap<>();
        if (user != null) {
            additionalInfo.put("username", user.getUsername());
        } else {
            additionalInfo.put("username", str);
        }
        log.debug("str", str);
        ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);
        return accessToken;
    }
}
