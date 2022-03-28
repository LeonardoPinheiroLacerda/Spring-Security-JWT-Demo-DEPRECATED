package com.leonardo.securityjwtdemo.security.users;

import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Data

public class AppUserCredentialsDTO {
    
    private String username;
    private String password;

}
