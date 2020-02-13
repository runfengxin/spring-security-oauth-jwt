package com.service.hi.servicehi.config;

import com.service.hi.servicehi.utils.HttpUtilsResultVO;
import com.service.hi.servicehi.utils.ResponseVo;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 无效Token返回处理器
 */
@Component
public class MyTokenExceptionEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.setStatus(HttpStatus.OK.value());
        response.setHeader("Content-Type", "application/json;charset=UTF-8");
        try {
                HttpUtilsResultVO.writerError(new ResponseVo(401, authException.getMessage()), response);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
