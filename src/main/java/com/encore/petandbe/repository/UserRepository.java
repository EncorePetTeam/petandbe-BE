package com.encore.petandbe.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.encore.petandbe.model.user.user.User;

public interface UserRepository extends JpaRepository<User, String> {

	Optional<User> findByEmail(String email);
}