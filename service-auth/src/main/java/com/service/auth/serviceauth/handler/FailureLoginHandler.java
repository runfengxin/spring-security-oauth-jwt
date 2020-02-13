package com.service.auth.serviceauth.handler;

import cn.hutool.json.JSON;
import com.service.auth.serviceauth.utils.HttpUtilsResultVO;
import com.service.auth.serviceauth.utils.ResponseVo;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class FailureLoginHandler extends SimpleUrlAuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        logger.info("登录失败");
        //设置状态码
        //将 登录失败 信息打包成json格式返回
        ResponseVo resultVo = new ResponseVo(HttpStatus.UNAUTHORIZED.value(), "登录失败");
        HttpUtilsResultVO.writerError(resultVo, response);
    }
}
