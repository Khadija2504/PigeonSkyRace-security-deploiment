package com.PigeonSkyRace.Pigeon.config;

import com.PigeonSkyRace.Pigeon.security.JwtRequestFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {

    @Bean
    public FilterRegistrationBean<JwtRequestFilter> jwtFilterRegistration(JwtRequestFilter filter) {
        FilterRegistrationBean<JwtRequestFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(filter);
        registrationBean.addUrlPatterns("/api/breeder/*");
        return registrationBean;
    }
}
