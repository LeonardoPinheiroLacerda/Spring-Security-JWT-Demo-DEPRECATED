package com.leonardo.securityjwtdemo.resources;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/ping")
public class PingResource {
    
    @GetMapping
    public ResponseEntity<String> ping(){
        return ResponseEntity.ok("ping");
    }

}
