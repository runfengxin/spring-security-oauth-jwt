package com.service.auth.serviceauth.config;

import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;

import javax.sql.DataSource;

public class MyJdbcClientDetailsService extends JdbcClientDetailsService {
    public MyJdbcClientDetailsService(DataSource dataSource) {
        super(dataSource);
    }


}
