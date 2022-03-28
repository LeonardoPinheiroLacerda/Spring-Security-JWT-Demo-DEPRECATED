package com.leonardo.securityjwtdemo.security.jwt.filters;

import java.io.IOException;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.leonardo.securityjwtdemo.security.jwt.JwtConfig;
import com.leonardo.securityjwtdemo.security.jwt.JwtUtil;
import com.leonardo.securityjwtdemo.security.users.AppUserCredentialsDTO;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JwtConfig jwtConfig;
    private final JwtUtil jwtUtil;
    private final SecretKey secretKey;


    public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager,
        JwtConfig jwtConfig,
        JwtUtil jwtUtil,
        SecretKey secretKey) {

        this.authenticationManager = authenticationManager;
        this.jwtConfig = jwtConfig;
        this.jwtUtil = jwtUtil;
        this.secretKey = secretKey;
    }

    @Override
    public Authentication attemptAuthentication(
        HttpServletRequest request,
        HttpServletResponse response) throws AuthenticationException {

        try {
            AppUserCredentialsDTO authenticationRequest = new ObjectMapper()
                    .readValue(request.getInputStream(), AppUserCredentialsDTO.class);

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getUsername(),
                    authenticationRequest.getPassword());

            Authentication authenticate = authenticationManager.authenticate(authentication);

            return authenticate;

        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

    @Override
    protected void successfulAuthentication(
        HttpServletRequest request,
        HttpServletResponse response, 
        FilterChain chain,
        Authentication authResult) throws IOException, ServletException {
        
        String token = jwtUtil.generateToken(authResult, jwtConfig, secretKey);
        
        response.addHeader("Authorization", jwtConfig.getTokenPrefix() + token);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException failed) throws IOException, ServletException {
        response.setStatus(401);
    }

    

}
