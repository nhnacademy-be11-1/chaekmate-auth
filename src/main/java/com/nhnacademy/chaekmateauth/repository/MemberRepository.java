package com.nhnacademy.chaekmateauth.repository;

import com.nhnacademy.chaekmateauth.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {
    Optional<Member> findByLoginIdAndDeletedAtIsNull(String loginId);
}