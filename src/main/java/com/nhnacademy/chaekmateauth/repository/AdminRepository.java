package com.nhnacademy.chaekmateauth.repository;

import com.nhnacademy.chaekmateauth.entity.Admin;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AdminRepository extends JpaRepository<Admin, Long> {
    boolean existsById(Long id);
    Optional<Admin> findByAdminLoginId(String adminLoginId);
}
