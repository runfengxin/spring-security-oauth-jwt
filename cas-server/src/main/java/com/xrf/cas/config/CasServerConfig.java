package com.xrf.cas.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "security.cas.server")
public class CasServerConfig {
    private String host;
    private String login;
    private String logout;

}
