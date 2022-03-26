package com.leonardo.securityjwtdemo.model.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter

public enum Authority {
    
    USER_READ ("user:read"),
    USER_WRITE ("user:write");

    private final String authority;

}
