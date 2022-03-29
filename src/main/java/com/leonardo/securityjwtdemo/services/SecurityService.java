package com.leonardo.securityjwtdemo.services;

import java.util.Optional;

import com.leonardo.securityjwtdemo.model.AppUser;
import com.leonardo.securityjwtdemo.repositories.UserRepository;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import lombok.AllArgsConstructor;

@AllArgsConstructor

@Service
public class SecurityService {
    
    private final UserRepository userRepository;
       
    public Optional<AppUser> getAuthenticateduUser(){
        String username = (String) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Optional<AppUser> user = userRepository.findByUsername(username);
        return user;
    }

}
