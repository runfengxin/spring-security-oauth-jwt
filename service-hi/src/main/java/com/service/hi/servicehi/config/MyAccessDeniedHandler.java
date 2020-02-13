package com.service.hi.servicehi.config;

import com.service.hi.servicehi.utils.HttpUtilsResultVO;
import com.service.hi.servicehi.utils.ResponseVo;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 无权访问处理器
 */
@Component
public class MyAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        ResponseVo resultVo = new ResponseVo();
        resultVo.setMessage("无权访问!");
        resultVo.setCode(403);
        HttpUtilsResultVO.writerError(resultVo, response);
    }
}
