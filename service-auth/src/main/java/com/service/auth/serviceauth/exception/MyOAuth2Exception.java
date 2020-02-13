package com.service.auth.serviceauth.exception;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

/**
 * 自定义异常处理
 */
@JsonSerialize(using = MyOAuthExceptionJacksonSerializer.class)
public class MyOAuth2Exception extends OAuth2Exception {

    private Integer code;

    public MyOAuth2Exception(String msg, Throwable t) {
        super(msg, t);
    }
    public MyOAuth2Exception(Integer code, String msg) {
        super(msg);
        this.code = code;
    }

    public int getHttpErrorCode() {
        return this.code;
    }
}
