package com.leonardo.securityjwtdemo.resources;

import com.leonardo.securityjwtdemo.model.AppUser;
import com.leonardo.securityjwtdemo.services.SecurityService;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.AllArgsConstructor;

@AllArgsConstructor

@RestController
@RequestMapping("/ping")
public class PingResource {
    
    private final SecurityService securityService;

    @GetMapping
    public ResponseEntity<AppUser> ping(){
        AppUser user = securityService.getAuthenticatedUser().get();
        user.setPassword("Hoje não XD");
        return ResponseEntity.ok(user);
    }

}
