package com.test.lsy.jwtreview1.repository;

import com.test.lsy.jwtreview1.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    public User findByUsername(String username);
}
