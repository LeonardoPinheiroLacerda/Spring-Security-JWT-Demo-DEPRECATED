package com.leonardo.securityjwtdemo.security.jwt;

import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Data

public class CredentialsRequest {
    
    private String username;
    private String password;

}
