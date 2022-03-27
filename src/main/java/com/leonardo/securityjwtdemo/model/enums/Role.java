package com.leonardo.securityjwtdemo.model.enums;

import java.util.Set;
import java.util.stream.Collectors;

import com.google.common.collect.Sets;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter

public enum Role {
    
    COMMON (
		Sets.newHashSet(
			Authority.USER_READ
		)
	),
    ADMIN (
		Sets.newHashSet(
			Authority.USER_READ, 
			Authority.USER_WRITE
		)
	);

    private final Set<Authority> authorities;

    public Set<SimpleGrantedAuthority> getAuthorities(){
		
		Set<SimpleGrantedAuthority> set = authorities
				.stream()
				.map(authority -> new SimpleGrantedAuthority(authority.getAuthority()))
				.collect(Collectors.toSet());
		
		set.add(new SimpleGrantedAuthority("ROLE_" + name()));
		
		return set;
		
	}

}
