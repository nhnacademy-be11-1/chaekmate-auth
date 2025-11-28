package com.nhnacademy.chaekmateauth.util;

import com.nhnacademy.chaekmateauth.common.properties.JwtProperties;
import com.nhnacademy.chaekmateauth.exception.AuthErrorCode;
import com.nhnacademy.chaekmateauth.exception.AuthException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Component
@RequiredArgsConstructor
public class MemberIdEncryptor {

    private final JwtProperties jwtProperties;
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding"; // ECB -> 블록 단위 암호화, PKCS5 패딩방식

    // meberId 암호화
    public String encryptMemberId(Long memberId) {
        try {
            // JWT secret을 키로 사용
            byte[] key = getKeyBytes();
            SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey); // 암호화 모드

            byte[] encrypted = cipher.doFinal(String.valueOf(memberId).getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(encrypted);
        } catch (Exception e) {
            throw new AuthException(AuthErrorCode.INTERNAL_SERVER_ERROR, e);
        }
    }

    // 복호화, 나중에 memberId추출할때 쓸 수 있음
    public Long decryptMemberId(String encryptedId) {
        try {
            byte[] key = getKeyBytes();
            SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey); // 복호화 모드

            byte[] decrypted = cipher.doFinal(Base64.getUrlDecoder().decode(encryptedId));
            return Long.parseLong(new String(decrypted, StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new AuthException(AuthErrorCode.INTERNAL_SERVER_ERROR, e);
        }
    }


    // JWT secret을 16바이트 키로 변환
    private byte[] getKeyBytes() {
        String secret = jwtProperties.getSecret();
        byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
        byte[] key = new byte[16];

        // secret을 16바이트로 변환
        for (int i = 0; i < 16; i++) {
            key[i] = secretBytes[i % secretBytes.length];
        }

        return key;
    }
}

