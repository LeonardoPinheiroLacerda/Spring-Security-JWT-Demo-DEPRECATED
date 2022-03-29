package com.leonardo.securityjwtdemo.services;

import java.util.Optional;

import javax.crypto.SecretKey;
import javax.servlet.http.HttpServletResponse;

import com.leonardo.securityjwtdemo.model.AppUser;
import com.leonardo.securityjwtdemo.security.jwt.JwtConfig;
import com.leonardo.securityjwtdemo.security.jwt.JwtUtil;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import lombok.AllArgsConstructor;

@AllArgsConstructor

@Service
public class SecurityService {
    
    private final JwtUtil jwtUtil;
    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;
       
    public Optional<AppUser> getAuthenticatedUser(){
        Optional<AppUser> user = Optional.of((AppUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal());
        return user;
    }

    public void refreshToken(HttpServletResponse response){
        response.addHeader(jwtConfig.getAuthorizationHeaderName(), jwtUtil.generateToken(getAuthenticatedUser().get(), jwtConfig, secretKey));
        response.setStatus(200);
    }

}
