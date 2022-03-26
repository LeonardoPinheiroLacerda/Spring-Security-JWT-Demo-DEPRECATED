package com.leonardo.securityjwtdemo.repositories;

import java.util.Optional;

import com.leonardo.securityjwtdemo.model.User;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Integer> {
    
    @Query("SELECT user FROM User user WHERE user.username = ?1")
    public Optional<User> findByUsername(String username);

}
