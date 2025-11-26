package com.nhnacademy.chaekmateauth.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nhnacademy.chaekmateauth.common.properties.PaycoOAuthProperties;
import com.nhnacademy.chaekmateauth.dto.TokenPair;
import com.nhnacademy.chaekmateauth.dto.request.LoginRequest;
import com.nhnacademy.chaekmateauth.dto.response.PaycoMemberInfoResponse;
import com.nhnacademy.chaekmateauth.dto.response.PaycoTempInfo;
import com.nhnacademy.chaekmateauth.dto.response.PaycoTempInfoResponse;
import com.nhnacademy.chaekmateauth.dto.response.PaycoTokenResponse;
import com.nhnacademy.chaekmateauth.entity.Admin;
import com.nhnacademy.chaekmateauth.entity.Member;
import com.nhnacademy.chaekmateauth.exception.AuthErrorCode;
import com.nhnacademy.chaekmateauth.exception.AuthException;
import com.nhnacademy.chaekmateauth.repository.AdminRepository;
import com.nhnacademy.chaekmateauth.repository.MemberRepository;
import com.nhnacademy.chaekmateauth.util.JwtTokenProvider;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    @Value("${spring.profiles.active}")
    private String activeProfile;

    private static final String REFRESH_TOKEN_PREFIX = "refresh";
    private static final String PAYCO_TEMP_INFO_PREFIX = "payco:temp:";

    // PAYCO API URL (고정값)
    private static final String PAYCO_AUTHORIZE_URL = "https://id.payco.com/oauth2.0/authorize";
    private static final String PAYCO_TOKEN_URL = "https://id.payco.com/oauth2.0/token";
    private static final String PAYCO_MEMBER_INFO_URL = "https://apis-payco.krp.toastoven.net/payco/friends/find_member_v2.json";
    private static final String PAYCO_RESPONSE_TYPE = "code";
    private static final String PAYCO_SERVICE_PROVIDER_CODE = "FRIENDS";
    private static final String PAYCO_USER_LOCALE = "ko_KR";
    private static final String PAYCO_SCOPE = "name,email,mobile";

    private static final String PARAM_CLIENT_ID = "client_id";
    private static final String PARAM_CLIENT_SECRET = "client_secret";
    private static final String PARAM_ACCESS_TOKEN = "access_token";

    private final JwtTokenProvider jwtTokenProvider;
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final AdminRepository adminRepository;
    private final RedisTemplate<String, String> redisTemplate;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    private final PaycoOAuthProperties paycoOAuthProperties;
    private final DoorayService doorayService;

    public TokenPair memberLogin(LoginRequest request) {
        Optional<Member> memberOpt = memberRepository.findByLoginId(request.loginId());
        if (memberOpt.isPresent()) {
            Member member = memberOpt.get();
            if (passwordEncoder.matches(request.password(), member.getPassword())) {

                // 휴면 계정 체크 (3개월 이상 미접속)
                if (Objects.nonNull(member.getLastLoginAt()) && isDormantMember(member.getLastLoginAt())) {
                    // Dooray 메시지로 인증번호 전송
                    doorayService.sendDormantVerificationCode(member.getId());
                    // 휴면 회원 예외 발생
                    throw new AuthException(AuthErrorCode.DORMANT_MEMBER);
                }

                // 일반 회원: 로그인 처리
                member.updateLastLoginAt();
                memberRepository.save(member);
                return jwtTokenProvider.createTokenPair(member.getId(), JwtTokenProvider.getTypeMember());
            }
        }
        throw new AuthException(AuthErrorCode.INVALID_CREDENTIALS);
    }

    private boolean isDormantMember(LocalDateTime lastLoginAt) {
        if (lastLoginAt == null) {
            return true; // 로그인한 적이 없으면 휴면
        }

        LocalDateTime threeMonthsAgo = LocalDateTime.now().minusMonths(3);
        return lastLoginAt.isBefore(threeMonthsAgo);
    }

    public TokenPair activateDormantMember(String loginId, String verificationCode) {
        // 회원 조회
        Member member = memberRepository.findByLoginId(loginId)
                .orElseThrow(() -> new AuthException(AuthErrorCode.MEMBER_NOT_FOUND));

        // 인증번호 검증
        boolean isValid = doorayService.verifyCode(member.getId(), verificationCode);
        if (!isValid) {
            throw new AuthException(AuthErrorCode.INVALID_VERIFICATION_CODE);
        }

        // 인증되면 휴면 해제해줌(lastLoginAt 업데이트)
        member.updateLastLoginAt();
        memberRepository.save(member);

        // 로그인 처리해줌(토큰 발급)
        return jwtTokenProvider.createTokenPair(member.getId(), JwtTokenProvider.getTypeMember());
    }

    public TokenPair adminLogin(LoginRequest request) {
        Optional<Admin> adminOpt = adminRepository.findByAdminLoginId(request.loginId());
        if (adminOpt.isPresent()) {
            Admin admin = adminOpt.get();
            if (passwordEncoder.matches(request.password(), admin.getAdminPassword())) {
                return jwtTokenProvider.createTokenPair(admin.getId(), JwtTokenProvider.getTypeAdmin());
            }
        }

        throw new AuthException(AuthErrorCode.INVALID_CREDENTIALS);
    }

    // refreshToken메서드
    public TokenPair refreshToken(String refreshToken) {
        // refreshToken검증
        if (!jwtTokenProvider.validateRefreshToken(refreshToken)) {
            throw new AuthException(AuthErrorCode.REFRESH_TOKEN_INVALID);
        }

        Long memberId = jwtTokenProvider.getMemberIdFromToken(refreshToken);
        String userType = jwtTokenProvider.getUserTypeFromToken(refreshToken);

        // Redis에서도 refreshToken 검증
        String redisKey = REFRESH_TOKEN_PREFIX + ":" + memberId;
        String storedRefreshToken = redisTemplate.opsForValue().get(redisKey);

        if (storedRefreshToken == null || !storedRefreshToken.equals(refreshToken)) {
            throw new AuthException(AuthErrorCode.REFRESH_TOKEN_INVALID);
        }

        // 새로운 토큰 생성
        TokenPair newTokenPair = jwtTokenProvider.createTokenPair(memberId, userType);

        // Redis 업데이트 (기존 삭제, 새로 저장)
        long refreshExpirationMillis = jwtTokenProvider.getRefreshTokenExpiration() * 1000;
        Boolean success = redisTemplate.opsForValue().setIfPresent(
                redisKey,
                newTokenPair.refreshToken(),
                Duration.ofMillis(refreshExpirationMillis)
        );

        if (!Boolean.TRUE.equals(success)) {
            // 다른 요청이 먼저 토큰을 변경했거나 토큰이 이미 삭제됨
            throw new AuthException(AuthErrorCode.REFRESH_TOKEN_INVALID);
        }

        return newTokenPair;
    }
    public String getPaycoAuthorizationUrl() {
        // 프로파일에 따라 redirect_uri 결정
        String redirectUri = paycoOAuthProperties.getRedirectUri();

        // prod 프로파일이면 HTTPS로 변경, dev면 그대로 사용
        if (redirectUri != null && !"dev".equalsIgnoreCase(activeProfile) && redirectUri.startsWith("http://")) {
            // prod 환경: HTTP를 HTTPS로 변경
                redirectUri = redirectUri.replace("http://", "https://");
                log.info("프로덕션 환경: redirect_uri를 HTTPS로 변경: {}", redirectUri);
        }

         //String authorizationUrl = UriComponentsBuilder.fromHttpUrl(PAYCO_AUTHORIZE_URL)
        String authorizationUrl = UriComponentsBuilder.fromUriString(PAYCO_AUTHORIZE_URL)
                .queryParam("response_type", PAYCO_RESPONSE_TYPE)  // 필수
                .queryParam(PARAM_CLIENT_ID, paycoOAuthProperties.getClientId())  // 필수
                .queryParam("serviceProviderCode", PAYCO_SERVICE_PROVIDER_CODE)  // 필수
                .queryParam("redirect_uri", URLEncoder.encode(redirectUri, StandardCharsets.UTF_8))  // 필수
                .queryParam("userLocale", PAYCO_USER_LOCALE)  // 필수
                .queryParam("scope", PAYCO_SCOPE)  // 이름, 이메일, 휴대폰 번호 정보 요청
                .build()
                .toUriString();

        log.debug("PAYCO Authorization URL 생성: profile={}, redirectUri={}", activeProfile, redirectUri);

        return authorizationUrl;
    }

    /**
     * PAYCO 콜백 처리: 기존 회원이면 바로 로그인, 없으면 임시 정보 저장
     * @return PaycoTempInfoResponse (기존 회원이면 token 포함, 신규 회원이면 tempInfo 포함)
     */
    public PaycoTempInfoResponse processPaycoCallback(String code) {
        // 1. 토큰 교환 (필수 파라미터만 사용)
        PaycoTokenResponse tokenResponse = exchangePaycoToken(code);

        // 2. 회원 정보 조회
        PaycoMemberInfoResponse memberInfo = getPaycoMemberInfo(tokenResponse.accessToken());

        if (memberInfo.data() == null || memberInfo.data().member() == null) {
            throw new AuthException(AuthErrorCode.MEMBER_NOT_FOUND);
        }

        String paycoId = memberInfo.data().member().idNo();
        // PAYCO에서 받은 실제 데이터 로그 출력
        String rawName = memberInfo.data().member().name();
        String rawEmail = memberInfo.data().member().email();
        String rawPhone = memberInfo.data().member().mobile();

        log.info("=== PAYCO에서 받은 원본 데이터 ===");
        log.info("idNo: {}", paycoId);
        log.info("name (원본): {}", rawName);
        log.info("email (원본): {}", rawEmail);
        log.info("mobile (원본): {}", rawPhone);
        log.info("=================================");

        // 기존 회원 조회 (paycoId를 loginId로 사용)
        Optional<Member> existingMember = memberRepository.findByLoginId(paycoId);

        if (existingMember.isPresent()) {
            // 기존 회원: 바로 로그인 처리
            log.info("기존 PAYCO 회원 발견: paycoId={}", paycoId);
            Member member = existingMember.get();
            member.updateLastLoginAt();
            memberRepository.save(member);

            TokenPair tokenPair = jwtTokenProvider.createTokenPair(member.getId(), JwtTokenProvider.getTypeMember());

            // Redis에 RefreshToken 저장
            String redisKey = REFRESH_TOKEN_PREFIX + ":" + member.getId();
            long refreshExpirationMillis = jwtTokenProvider.getRefreshTokenExpiration() * 1000;
            redisTemplate.opsForValue().set(redisKey, tokenPair.refreshToken(),
                    Duration.ofMillis(refreshExpirationMillis));

            String name = rawName != null && !rawName.trim().isEmpty() ? rawName : null;

            return new PaycoTempInfoResponse(
                    null,  // tempKey 없음
                    paycoId,
                    name,
                    rawEmail,
                    rawPhone,
                    true,  // 기존 회원
                    tokenPair.accessToken(),
                    tokenPair.refreshToken()
            );
        } else {
            // 신규 회원: 임시 정보 저장 후 회원가입 페이지로
            log.info("신규 PAYCO 회원: paycoId={}", paycoId);

            String name = rawName != null && !rawName.trim().isEmpty()
                    ? rawName
                    : null;

            // PAYCO에서 제공하는 정보 (회원가입 시 입력한 정보)
            String email = rawEmail;
            String phone = rawPhone;  // PAYCO API는 mobile 필드 사용

            log.info("=== 저장할 PAYCO 정보 ===");
            log.info("paycoId: {}", paycoId);
            log.info("name (저장): {}", name);
            log.info("email (저장): {}", email);
            log.info("phone (저장): {}", phone);
            log.info("========================");

            PaycoTempInfo tempInfo = new PaycoTempInfo(paycoId, name, email, phone);

            // Redis에 임시 저장 (10분 유효, tempKey는 제외하고 저장)
            String tempKey = UUID.randomUUID().toString();
            String redisKey = PAYCO_TEMP_INFO_PREFIX + tempKey;

            try {
                String json = objectMapper.writeValueAsString(tempInfo);
                redisTemplate.opsForValue().set(redisKey, json, Duration.ofMinutes(10));
            } catch (JsonProcessingException e) {
                log.error("PAYCO 임시 정보 저장 실패", e);
                throw new AuthException(AuthErrorCode.INTERNAL_SERVER_ERROR);
            }

            return new PaycoTempInfoResponse(
                    tempKey,
                    paycoId,
                    name,
                    email,
                    phone,
                    false,  // 신규 회원
                    null,   // token 없음
                    null    // token 없음
            );
        }
    }

    /**
     * PAYCO 임시 정보 조회
     */
    public PaycoTempInfoResponse getPaycoTempInfo(String tempKey) {
        String redisKey = PAYCO_TEMP_INFO_PREFIX + tempKey;
        String json = redisTemplate.opsForValue().get(redisKey);

        if (json == null) {
            throw new AuthException(AuthErrorCode.MEMBER_NOT_FOUND);
        }

        try {
            // Redis에 저장된 정보는 tempKey 없이 저장되었으므로, PaycoTempInfo로 읽고 tempKey를 포함하여 반환
            PaycoTempInfo tempInfo = objectMapper.readValue(json, PaycoTempInfo.class);
            return new PaycoTempInfoResponse(
                    tempKey,
                    tempInfo.paycoId(),
                    tempInfo.name(),
                    tempInfo.email(),
                    tempInfo.phone(),
                    false,  // 신규 회원
                    null,   // token 없음
                    null    // token 없음
            );
        } catch (JsonProcessingException e) {
            log.error("PAYCO 임시 정보 조회 실패", e);
            throw new AuthException(AuthErrorCode.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * PAYCO 임시 정보 삭제 (회원가입 완료 후)
     */
    public void deletePaycoTempInfo(String tempKey) {
        String redisKey = PAYCO_TEMP_INFO_PREFIX + tempKey;
        redisTemplate.delete(redisKey);
    }

    /**
     * PAYCO 회원가입 후 자동 로그인
     * PAYCO idNo로 회원 조회 후 토큰 발급
     */
    public TokenPair paycoAutoLogin(String paycoId) {
        Optional<Member> memberOpt = memberRepository.findByLoginId(paycoId);
        if (memberOpt.isEmpty()) {
            throw new AuthException(AuthErrorCode.MEMBER_NOT_FOUND);
        }

        Member member = memberOpt.get();
        member.updateLastLoginAt();
        memberRepository.save(member);

        TokenPair tokenPair = jwtTokenProvider.createTokenPair(member.getId(), JwtTokenProvider.getTypeMember());

        // Redis에 RefreshToken 저장
        String redisKey = REFRESH_TOKEN_PREFIX + ":" + member.getId();
        long refreshExpirationMillis = jwtTokenProvider.getRefreshTokenExpiration() * 1000;
        redisTemplate.opsForValue().set(redisKey, tokenPair.refreshToken(),
                Duration.ofMillis(refreshExpirationMillis));

        return tokenPair;
    }

    /**
     * Authorization Code를 Access Token으로 교환 (필수 파라미터만 사용)
     */
    private PaycoTokenResponse exchangePaycoToken(String code) {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");  // 필수
        params.add(PARAM_CLIENT_ID, paycoOAuthProperties.getClientId());  // 필수
        params.add(PARAM_CLIENT_SECRET, paycoOAuthProperties.getClientSecret());  // 필수
        params.add("code", code);  // 필수

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        try {
            ResponseEntity<PaycoTokenResponse> response = restTemplate.exchange(
                    PAYCO_TOKEN_URL,
                    HttpMethod.POST,
                    request,
                    PaycoTokenResponse.class
            );

            if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
                log.error("PAYCO 토큰 교환 실패: {}", response.getStatusCode());
                throw new AuthException(AuthErrorCode.TOKEN_INVALID);
            }

            return response.getBody();
        } catch (Exception e) {
            log.error("PAYCO 토큰 교환 중 오류 발생", e);
            throw new AuthException(AuthErrorCode.TOKEN_INVALID);
        }
    }

    /**
     * PAYCO 회원 정보 조회 (필수 파라미터만 사용)
     */
    private PaycoMemberInfoResponse getPaycoMemberInfo(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.set(PARAM_CLIENT_ID, paycoOAuthProperties.getClientId());  // 필수
        headers.set(PARAM_ACCESS_TOKEN, accessToken);  // 필수

        HttpEntity<Map<String, Object>> request = new HttpEntity<>(new HashMap<>(), headers);

        try {
            // 실제 JSON 응답을 확인하기 위해 String으로 먼저 받기
            ResponseEntity<String> rawResponse = restTemplate.exchange(
                    PAYCO_MEMBER_INFO_URL,
                    HttpMethod.POST,
                    request,
                    String.class
            );

            log.info("PAYCO 회원 정보 조회 API 응답 상태: {}", rawResponse.getStatusCode());
            log.info("=== PAYCO API 원본 JSON 응답 ===");
            log.info("{}", rawResponse.getBody());
            log.info("===============================");

            if (!rawResponse.getStatusCode().is2xxSuccessful() || rawResponse.getBody() == null) {
                log.error("PAYCO 회원 정보 조회 실패: {}", rawResponse.getStatusCode());
                throw new AuthException(AuthErrorCode.MEMBER_NOT_FOUND);
            }

            // String을 PaycoMemberInfoResponse로 변환
            PaycoMemberInfoResponse body = objectMapper.readValue(rawResponse.getBody(), PaycoMemberInfoResponse.class);

            if (body.header() == null || !body.header().isSuccessful()) {
                log.error("PAYCO 회원 정보 조회 실패: {}", body.header());
                throw new AuthException(AuthErrorCode.MEMBER_NOT_FOUND);
            }

            // PAYCO API 응답 전체 로그 출력 (디버깅용)
            log.info("=== PAYCO API 전체 응답 ===");
            log.info("Header: isSuccessful={}, resultCode={}, resultMessage={}",
                    body.header().isSuccessful(), body.header().resultCode(), body.header().resultMessage());
            if (body.data() != null && body.data().member() != null) {
                log.info("Member 전체 정보: {}", body.data().member());
            } else {
                log.warn("Member 정보가 null입니다");
            }
            log.info("=========================");

            return body;
        } catch (Exception e) {
            log.error("PAYCO 회원 정보 조회 중 오류 발생", e);
            throw new AuthException(AuthErrorCode.MEMBER_NOT_FOUND);
        }
    }
}
