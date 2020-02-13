package com.service.auth.serviceauth.exception;

import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.stereotype.Component;

@Component("MyOAuth2WebResponseExceptionTranslator")
public class MyOAuth2WebResponseExceptionTranslator implements WebResponseExceptionTranslator<OAuth2Exception> {

    @Override
    public ResponseEntity<OAuth2Exception> translate(Exception e) {
        OAuth2Exception oAuth2Exception = (OAuth2Exception) e;
        return ResponseEntity.status(200)
                .body(new MyOAuth2Exception(oAuth2Exception.getHttpErrorCode(), oAuth2Exception.getMessage()));
    }
}
