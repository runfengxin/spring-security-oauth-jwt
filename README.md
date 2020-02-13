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
![请求结果](https://github.com/runfengxin/spring-security-oauth-jwt/blob/master/others/images/1.png) 

access_token的主要作用是请求需要认证的接口，refresh_token的主要作用是用来刷新access_token的，
所以一般refresh_token的过期时间会比access_token的过期时间长，为什么要刷新token呢？因为在实际情况下，
你的access_token是暴露给客户端的，而且设置的过期时间很长，如果有人恶意截取你的token去请求接口，
后果不堪设想。当然，refresh_token也可能被同时截取，所以两个token过期时间需要根据实际情况尽可能缩短。
那有人会有一个问题，刷新token后悔
    