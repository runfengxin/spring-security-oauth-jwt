package com.service.hi.servicehi.controller;

import com.service.hi.servicehi.dto.UserDao;
import com.service.hi.servicehi.dto.UserService;
import com.service.hi.servicehi.entity.User;
import com.service.hi.servicehi.utils.BPwdEncoderUtil;
import com.service.hi.servicehi.utils.ResponseVo;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RestController
public class TestEndPointController {

    Logger logger = LoggerFactory.getLogger(TestEndPointController.class);

    @Autowired
    private UserService userService;

    @Autowired
    private UserDao userRepository;

    @Autowired
    private ConsumerTokenServices consumerTokenServices;

    @GetMapping("/product/{id}")
    public String getProduct(@PathVariable String id) {

        String dbpasswor = "$2a$10$HBX6q6TndkgMxhSEdoFqWOUtctaJEMoXe49NWh8Owc.4MTunv.wXa";

        logger.info("判断两个密码是否相等 " + (BPwdEncoderUtil.matches("123456", dbpasswor)));

        return "product id : " + id;
    }

    @GetMapping("/order/{id}")
        public String getOrder(@PathVariable String id) {
            return "order id : " + id;
        }

        @GetMapping("/getPrinciple")
        public OAuth2Authentication getPrinciple(OAuth2Authentication oAuth2Authentication, Principal principal, Authentication authentication) {
            logger.info(oAuth2Authentication.getUserAuthentication().getAuthorities().toString());
            logger.info(oAuth2Authentication.toString());
            logger.info("principal.toString() " + principal.toString());
            logger.info("principal.getName() " + principal.getName());
            logger.info("authentication: " + authentication.getAuthorities().toString());

            return oAuth2Authentication;
        }

        @RequestMapping(value = "/registry", method = RequestMethod.POST)
        public User createUser(@RequestParam("username") String username, @RequestParam("password") String password) {
            if (StringUtils.isNotEmpty(username) && StringUtils.isNotEmpty(password)) {
                return userService.create(username, password);
            }

            return null;
        }

        @PreAuthorize("hasAnyAuthority('ROLE_ADMIN')")
        @RequestMapping("/hello")
        public String hello() {

            return "hello you";
        }

        @GetMapping("/logout/{accessToken}")
        public ResponseVo logout(@PathVariable String accessToken) {
        accessToken="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1Nzg5NDE1MzQsInVzZXJfbmFtZSI6InhpbiIsImp0aSI6ImU1Y2YyOWMwLTZmNzYtNDA0Mi1hOTdlLTNkODhhYWE3ZjJmOSIsImNsaWVudF9pZCI6InByb2R1Y3QtdmlldyIsInNjb3BlIjpbInNlcnZlciJdfQ.WnW2xpFlgLwc9aum6Ir1auq8CPSxYTmZiZwhUmrxFIHHlNWi9CPHtD3vZADQvW2bCKY36G3LDKXNJ7T-74lK9V53OjBG-cAjqvGjsZ3flnvz16vn-RE-pJfzFUSe0S7zV93VcTVAqFB2U0biQdC9dpcwRta6QH5BwZwEq2LtDPnBtPmfSCzE7EShaG0IOwwBpwmLcuhrX6MOrNvqY8HO5d9GAGG1Eqaphs8SptFn0N5mVyq3mTTTLVqbqFegiG9frj21UCCbpWLyLSVUlLRtg1j8Pwv-a3EgzTBjhfASu1JygjaK3OojhqKXuXKqYENBBtHZZv8khq-4Y9w3f87CSA";
        if (consumerTokenServices.revokeToken(accessToken)) {
            return new ResponseVo(200, "登出成功");
        } else {
            return new ResponseVo(500, "登出失败");
        }
    }

}
