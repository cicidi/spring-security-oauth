package com.baeldung.resource.spring;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

import java.util.jar.JarEntry;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  private String jwkSetUri = "http://localhost:8083/auth/realms/electroknox-dev/protocol/openid-connect/certs";

  @Override
  protected void configure(HttpSecurity http) throws Exception {// @formatter:off
    http.cors()
      .and()
      .authorizeRequests()
      .antMatchers(HttpMethod.GET, "/user/info", "/api/foos/**")
      .hasRole("admin")
      .antMatchers(HttpMethod.POST, "/api/foos")
      .hasAnyAuthority("SCOPE_write")
      .anyRequest()
      .authenticated()
      .and()
      .oauth2ResourceServer(
        oauth2ResourceServer -> oauth2ResourceServer.jwt(
          jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
      );
  }//@formatter:on

  private Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter() {
    JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
    jwtConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRealmRoleConverter());
    return jwtConverter;
  }

  @Bean
  JwtDecoder jwtDecoder() {
    return NimbusJwtDecoder.withJwkSetUri(this.jwkSetUri).build();
  }

}
