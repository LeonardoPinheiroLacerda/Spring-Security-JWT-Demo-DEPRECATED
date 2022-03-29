package com.leonardo.securityjwtdemo.resources;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.leonardo.securityjwtdemo.services.SecurityService;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.AllArgsConstructor;

@AllArgsConstructor

@RestController
@RequestMapping("/auth")
public class AuthResource {
    
    private final SecurityService securityService;

    @GetMapping(value = "/refresh-token")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response){
        securityService.refreshToken(response);
    }

}
