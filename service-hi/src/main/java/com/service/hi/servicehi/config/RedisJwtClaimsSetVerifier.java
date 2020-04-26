package com.service.hi.servicehi.config;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.token.store.JwtClaimsSetVerifier;

import java.util.Map;

/**
 * jwt自定义验证类
 */
public class RedisJwtClaimsSetVerifier implements JwtClaimsSetVerifier {

    private RedisTemplate redisTemplate;

    public RedisJwtClaimsSetVerifier(RedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void verify(Map<String, Object> map) throws InvalidTokenException {
        if (map.containsKey("jti")) {
            String jti = map.get("jti").toString();
            Object value = redisTemplate.opsForValue().get(jti);
            if (value == null) {
                throw new InvalidTokenException("无效的令牌");
            }
        }
    }
}
