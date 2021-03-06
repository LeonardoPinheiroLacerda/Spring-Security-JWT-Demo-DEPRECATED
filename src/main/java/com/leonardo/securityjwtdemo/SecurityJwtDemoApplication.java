package com.leonardo.securityjwtdemo;

import java.util.Arrays;

import com.google.common.collect.Sets;
import com.leonardo.securityjwtdemo.model.AppUser;
import com.leonardo.securityjwtdemo.model.enums.Role;
import com.leonardo.securityjwtdemo.repositories.UserRepository;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.password.PasswordEncoder;


@SpringBootApplication
public class SecurityJwtDemoApplication implements CommandLineRunner{

	private final UserRepository repository;
	private final PasswordEncoder passwordEncoder;

	public SecurityJwtDemoApplication(UserRepository repository, PasswordEncoder passwordEncoder) {
		this.repository = repository;
		this.passwordEncoder = passwordEncoder;
	}

	public static void main(String[] args) {
		SpringApplication.run(SecurityJwtDemoApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		AppUser leonardo = new AppUser(null, "leonardo", passwordEncoder.encode("senha123"), Sets.newHashSet(Role.COMMON));
		AppUser claudia = new AppUser(null, "claudia", passwordEncoder.encode("123senha"), Sets.newHashSet(Role.COMMON, Role.ADMIN));

		repository.saveAll(Arrays.asList(leonardo, claudia));		
	}

}
