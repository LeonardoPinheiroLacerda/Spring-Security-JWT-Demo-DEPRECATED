package com.leonardo.securityjwtdemo.repositories;

import java.util.Optional;

import com.leonardo.securityjwtdemo.model.AppUser;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<AppUser, Integer> {
    
    @Query("SELECT user FROM AppUser user WHERE user.username = ?1")
    public Optional<AppUser> findByUsername(String username);

}
