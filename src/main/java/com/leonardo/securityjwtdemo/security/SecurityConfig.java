package com.leonardo.securityjwtdemo.security;

import javax.crypto.SecretKey;

import com.leonardo.securityjwtdemo.model.enums.Role;
import com.leonardo.securityjwtdemo.repositories.UserRepository;
import com.leonardo.securityjwtdemo.security.jwt.JwtConfig;
import com.leonardo.securityjwtdemo.security.jwt.JwtUtil;
import com.leonardo.securityjwtdemo.security.jwt.filters.TokenVerifier;
import com.leonardo.securityjwtdemo.security.jwt.filters.UsernameAndPasswordAuthentication;
import com.leonardo.securityjwtdemo.security.users.AppUserDetailsService;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import lombok.AllArgsConstructor;

@AllArgsConstructor

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter{

    private final JwtConfig jwtConfig;
    private final JwtUtil jwtUtil;
    private final SecretKey secretKey;
    private final UserRepository userRepository;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf().disable()

            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

            .and()

            .addFilter(new UsernameAndPasswordAuthentication(authenticationManager(), jwtConfig, jwtUtil, secretKey))
            .addFilterAfter(new TokenVerifier(jwtConfig, secretKey, userDetailsService()), UsernameAndPasswordAuthentication.class)
            
            /*
            Permite acesso ao banco de dados H2
            Para uma aplicação de produção, deletar essa linha ou restringir para profiles de teste ou desenvolvimento
            */
            .headers().frameOptions().disable()
            .and()
        
            .authorizeRequests()
            .antMatchers("/h2-console/**").permitAll()            
            .antMatchers(HttpMethod.GET, "/ping").hasRole(Role.ADMIN.name())
            .anyRequest()
            .authenticated();

    }
    
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder(5);
    }

    @Override
    protected UserDetailsService userDetailsService() {
        return new AppUserDetailsService(userRepository);
    }
  
}
