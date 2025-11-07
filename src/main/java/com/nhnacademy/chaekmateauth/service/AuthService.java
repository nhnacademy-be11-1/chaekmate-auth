package com.nhnacademy.chaekmateauth.service;

import com.nhnacademy.chaekmateauth.client.CoreClient;
import com.nhnacademy.chaekmateauth.dto.MemberResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {
    private final CoreClient coreClient;

    public Long getMemberIdByLonginId(String loginId){
        MemberResponse member = coreClient.getMemberByLoginId(loginId);
        return member.getId();
    }
}
