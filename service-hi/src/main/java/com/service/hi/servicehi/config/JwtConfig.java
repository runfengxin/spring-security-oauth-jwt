package com.service.hi.servicehi.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.util.FileCopyUtils;

import java.io.IOException;


/**
 * 令牌解码配置
 */
@Configuration
public class JwtConfig {

    public static final String public_cert = "public.cert";

//    @Autowired
//    private JwtAccessTokenConverter jwtAccessTokenConverter;

    @Autowired
    private RedisTemplate redisTemplate;

    @Bean
    protected JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        Resource resource =  new ClassPathResource(public_cert);

        String publicKey;
        try {
            publicKey = new String(FileCopyUtils.copyToByteArray(resource.getInputStream()));
        }catch (IOException e) {
            throw new RuntimeException(e);
        }

        converter.setVerifierKey(publicKey);
        return converter;
    }

    @Bean
    @Qualifier("tokenStore")
    public TokenStore tokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter()) {
            @Override
            public void removeAccessToken(OAuth2AccessToken token) {
                if (token.getAdditionalInformation().containsKey("jti")) {
                    String jti = token.getAdditionalInformation().get("jti").toString();
                    redisTemplate.delete(jti);
                }
                super.removeAccessToken(token);
            }
        };
    }


}
