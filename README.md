# Spring Security OAuth2 JWT相关集成(授权码和密码模式)
## Spring Security OAuth2基础学习参考资料：
https://blog.csdn.net/sinat_32023305/article/details/90719755
https://blog.csdn.net/xqhys/article/details/87178824

##关于jwt编解码
使用jks作为证书私钥格式  
关于jks：https://blog.csdn.net/propitious_cloud/article/details/79474160

jks证书生成命令（test-jwt.jks为文件名，test123为密码）  
```
keytool -genkeypair -alias test-jwt -validity 3650 -keyalg RSA -dname "CN=jwt,OU=jtw,O=jtw,L=zurich,S=zurich,C=CH" -keypass test123 -keystore test-jwt.jks -storepass test123
```
生成公钥命令(可以使用git bash执行)：
```
keytool -list -rfc --keystore test-jwt.jks | openssl x509 -inform pem -pubkey
``` 
在pom文件中增加不编译过滤  
```
<build>
 <plugins>
     <plugin>
         <groupId>org.apache.maven.plugins</groupId>
         <artifactId>maven-resources-plugin</artifactId>
         <configuration>
             <nonFilteredFileExtensions>
                 <nonFilteredFileExtension>cert</nonFilteredFileExtension>
                 <nonFilteredFileExtension>jks</nonFilteredFileExtension>
             </nonFilteredFileExtensions>
         </configuration>
     </plugin>
 </plugins>
</build>
```
## 关于token和refresh_token
由于本项目是使用jwt格式生成token，对于服务器而言是无状态的，不同于session  

jwt和session的区别可参考这个博客：https://www.cnblogs.com/yuanrw/p/10089796.html

通过/oauth/token 我们可以获取得到access_token和refresh_token(认证服务器需配置启动)  
如图： 
![/oauth/token认证结果](https://github.com/runfengxin/spring-security-oauth-jwt/blob/master/others/images/1.png)   

![/oauth/token刷新token请求和结果](https://github.com/runfengxin/spring-security-oauth-jwt/blob/master/others/images/2.png)  

access_token的主要作用是请求需要认证的接口，refresh_token的主要作用是用来获取新的access_token的，
当access_token过期时需要调用/oauth/token接口去获取新的access_token和新的refresh_token(注意：
refresh_token过期时间是不会变，跟第一次认证结果获取的refresh_token过期时间保持一致，而access_token的
过期时间会重置为设定值),所以一般refresh_token的过期时间会比access_token的过期时间长，为什么要
刷新token呢？因为在实际情况下，你的access_token是暴露给客户端的，而且设置的过期时间很长，如果
有人恶意截取你的token去请求接口，后果不堪设想。当然，refresh_token也可能被同时截取，所以两个token
过期时间需要根据实际情况尽可能缩短。

相关参数设置如下：
```
@Bean
@Primary
public DefaultTokenServices tokenServices() {
    DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
    //token存取方式
    defaultTokenServices.setTokenStore(tokenStore());
    //启动refresh_token模式
    defaultTokenServices.setSupportRefreshToken(true);
    // 如果没有设置它,JWT就失效了.
    defaultTokenServices.setTokenEnhancer(tokenEnhancer());
    //access_token过期时间  单位秒
    defaultTokenServices.setAccessTokenValiditySeconds((int)TimeUnit.HOURS.toSeconds(1));
    //refresh_token过期时间  单位秒
    defaultTokenServices.setRefreshTokenValiditySeconds((int)TimeUnit.HOURS.toSeconds(6));
    return defaultTokenServices;
}
```

## 关于请求前客户端认证拦截器
ClientDetailsAuthenticationFilter通过实现OncePerRequestFilter接口来重新客户端认证拦截，
一般套这个模板进行自定义一些内容，然后在认证服务配置的安全约束中加入拦截器
``` 
@Override
public void configure(AuthorizationServerSecurityConfigurer security) {
   // 客户端认证之前的过滤器
   clientDetailsAuthenticationFilter.setClientDetailsService(clientDetailsService());
   security.addTokenEndpointAuthenticationFilter(clientDetailsAuthenticationFilter);
   // 允许表单认证
   security.allowFormAuthenticationForClients().tokenKeyAccess("permitAll()")
           .checkTokenAccess("isAuthenticated()").allowFormAuthenticationForClients();
}
```

验证结果如下：  
![/oauth/token无客户端信息请求结果](https://github.com/runfengxin/spring-security-oauth-jwt/blob/master/others/images/3.png)  

## 关于自定义异常
通过继承OAuth2Exception类实现我的自定义异常处理类，并需要进行序列化处理成json个是，
可以参考exception包下的类，一般套用这几个类定制我们的异常处理内容，还需要将异常处理节点
添加到令牌端点上：  
```
endpoints.exceptionTranslator(webResponseExceptionTranslator);
```

验证结果如下：
![/oauth/token无grant_type信息请求结果](https://github.com/runfengxin/spring-security-oauth-jwt/blob/master/others/images/4.png)  


##关于自定义认证模式
本项目使用手机号+验证码认证模式进行扩展，真正执行用户的验证是在TokenGranter中进行的，
详细可回顾上面参考学习资料中提到的源码认证过程，从而可以进行优雅的扩展，大量减少不必要的
代码。  
通过继承AbstractTokenGranter实现我们自定义的认证，可参考SMSCodeTokenGranter
在授权服务器几个需要配置的地方：
```
    /**
     这是从spring 的代码中 copy出来的,默认的几个 TokenGranter
     */
    private List<TokenGranter> getDefaultTokenGranters() {
        ClientDetailsService clientDetails = clientDetailsService();
        AuthorizationServerTokenServices tokenServices = tokenServices();
        AuthorizationCodeServices authorizationCodeServices = authorizationCodeServices();
        OAuth2RequestFactory requestFactory = requestFactory();

        List<TokenGranter> tokenGranters = new ArrayList<TokenGranter>();
        tokenGranters.add(new AuthorizationCodeTokenGranter(tokenServices,
                authorizationCodeServices, clientDetails, requestFactory));
        tokenGranters.add(new RefreshTokenGranter(tokenServices, clientDetails, requestFactory));
        ImplicitTokenGranter implicit = new ImplicitTokenGranter(tokenServices, clientDetails,
                requestFactory);
        tokenGranters.add(implicit);
        tokenGranters.add(
                new ClientCredentialsTokenGranter(tokenServices, clientDetails, requestFactory));
        if (authenticationManager != null) {
            tokenGranters.add(new ResourceOwnerPasswordTokenGranter(authenticationManager,
                    tokenServices, clientDetails, requestFactory));
        }
        //添加手机验证码认证模式
        tokenGranters.add(new SMSCodeTokenGranter(tokenServices, clientDetails, requestFactory, userServiceDetail));
        return tokenGranters;
    }
    
    /**
     通过 tokenGranter 塞进去的就是它了
     */
    private TokenGranter tokenGranter() {
        TokenGranter tokenGranter = new TokenGranter() {
            private CompositeTokenGranter delegate;

            @Override
            public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
                if (delegate == null) {
                    delegate = new CompositeTokenGranter(getDefaultTokenGranters());
                }
                return delegate.grant(grantType, tokenRequest);
            }
        };
        return tokenGranter;
    }
```

再将定义好的tokenGranter添加到令牌端点
```
endpoints.tokenStore(tokenStore).tokenGranter(tokenGranter())
```

验证手机号+验证码登录结果：
![/oauth/token手机号+验证码请求结果](https://github.com/runfengxin/spring-security-oauth-jwt/blob/master/others/images/5.png)  

##关于自定义返回参数
可以通过实现TokenEnhancer接口定义自己的返回参数，详细参考CustomTokenEnhancer，然后在
认证服务配置中加入到tokenEnhancer链中，如下：
```
tokenEnhancerChain.setTokenEnhancers(Arrays.asList(new CustomTokenEnhancer(), jwtAccessTokenConverter()));
```

验证结果如下：
![/oauth/token自定义返回参数请求结果](https://github.com/runfengxin/spring-security-oauth-jwt/blob/master/others/images/6.png)  

##关于授权码模式配置
这里使用JDBC来存储授权码
```
private AuthorizationCodeServices authorizationCodeServices() {
    return new JdbcAuthorizationCodeServices(dataSource);  //使用JDBC存取授权码
}
```
将授权码服务接口添加到令牌端点
```
endpoints.authorizationCodeServices(authorizationCodeServices());
```

在安全管理器中添加相应的http
```
@Override
protected void configure(HttpSecurity http) throws Exception {
http
    // 必须配置，不然OAuth2的http配置不生效----不明觉厉
    .requestMatchers()
    .antMatchers("/auth/login", "/auth/authorize", "/oauth/authorize")
    .and()
    .authorizeRequests()
    // 自定义页面或处理url是，如果不配置全局允许，浏览器会提示服务器将页面转发多次
    .antMatchers("/auth/login", "/auth/authorize")
    .permitAll()
    .anyRequest()
    .authenticated();

// 表单登录
http.formLogin()
//       .failureHandler(failureLoginHandler)
        .successHandler(successLoginHandler)
        // 页面
        .loginPage("/auth/login")
        // 登录处理url
        .loginProcessingUrl("/auth/authorize");
        
http.httpBasic().disable();
}
```

在令牌端点上添加绑定自定义的授权页面接口
```
endpoints.pathMapping("/oauth/confirm_access","/custom/confirm_access");
```
/auth/login: 跳转登录页并返回登录认证接口/auth/authorize参数的接口
/auth/authorize： 登录认证接口
/oauth/authorize： 授权登录接口
/oauth/confirm_access：默认授权页面
/custom/confirm_access：跳转授权页面并返回相关参数的接口

验证步骤：
1.在url上输入以下地址：  
http://localhost:9098/oauth/authorize?response_type=code&client_id=product-view&client_secret=123456&redirect_uri=http://localhost:9000&scope=server  
如下图所示： 
![由于未登录跳转到登录页](https://github.com/runfengxin/spring-security-oauth-jwt/blob/master/others/images/7.png)   

2.因未登录，所以跳到登录页，输入正确用户密码后跳转到自定义的授权页面，如下图：  
![登录后跳转到授权页面](https://github.com/runfengxin/spring-security-oauth-jwt/blob/master/others/images/8.png)   

3.点击授权跳转到http://localhost:9000并携带code参数
![目标跳转页面](https://github.com/runfengxin/spring-security-oauth-jwt/blob/master/others/images/9.png)   
  
4.拿到code参数调用/oauth/token获取access_token
![/oauth/token请求参数](https://github.com/runfengxin/spring-security-oauth-jwt/blob/master/others/images/10.png)  
（注意：code是一次性的）

##关于认证成功和失败的处理器
详细可参考SuccessLoginHandler和FailureLoginHandler



    