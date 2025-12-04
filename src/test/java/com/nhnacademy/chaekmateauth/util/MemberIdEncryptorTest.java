package com.nhnacademy.chaekmateauth.util;

import com.nhnacademy.chaekmateauth.common.properties.JwtProperties;
import com.nhnacademy.chaekmateauth.exception.AuthErrorCode;
import com.nhnacademy.chaekmateauth.exception.AuthException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.BDDMockito.given;

@ActiveProfiles("test")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("NonAsciiCharacters")
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class MemberIdEncryptorTest {

    @Mock
    private JwtProperties jwtProperties;

    private MemberIdEncryptor memberIdEncryptor;

    private static final String TEST_SECRET_KEY = "randomSecretKeyForJwtTokenProviderTestingHmacSha256Algorithm123456789";

    @BeforeEach
    void setUp() {
        given(jwtProperties.getSecret()).willReturn(TEST_SECRET_KEY);
        memberIdEncryptor = new MemberIdEncryptor(jwtProperties);
    }

    @Test
    void memberId_암호화_복호화_성공() {
        Long memberId = 123L;

        String encrypted = memberIdEncryptor.encryptMemberId(memberId);
        Long decrypted = memberIdEncryptor.decryptMemberId(encrypted);

        assertThat(encrypted).isNotNull().isNotEmpty();
        assertThat(decrypted).isEqualTo(memberId);
    }

    @ParameterizedTest
    @ValueSource(longs = { 1L, 100L, 999L, 123456789L, Long.MAX_VALUE })
    void 다양한_memberId_암호화_복호화_성공(Long memberId) {
        String encrypted = memberIdEncryptor.encryptMemberId(memberId);
        Long decrypted = memberIdEncryptor.decryptMemberId(encrypted);

        assertThat(decrypted).isEqualTo(memberId);
    }

    @Test
    void 같은_memberId는_같은_암호화_결과_반환() {
        Long memberId = 123L;

        String encrypted1 = memberIdEncryptor.encryptMemberId(memberId);
        String encrypted2 = memberIdEncryptor.encryptMemberId(memberId);

        assertThat(encrypted1).isEqualTo(encrypted2);
    }

    @Test
    void 다른_secret_key로_암호화한_값은_복호화_실패() {
        Long memberId = 123L;

        String encrypted = memberIdEncryptor.encryptMemberId(memberId);

        JwtProperties otherProperties = new JwtProperties();
        otherProperties.setSecret("DifferentSecretKey_AtLeast_64bytes_ForHMACSHA256Algorithm_Different");
        MemberIdEncryptor otherEncryptor = new MemberIdEncryptor(otherProperties);

        assertThatThrownBy(() -> otherEncryptor.decryptMemberId(encrypted))
                .isInstanceOf(AuthException.class)
                .extracting("errorCode")
                .isEqualTo(AuthErrorCode.INTERNAL_SERVER_ERROR);
    }

    @Test
    void 잘못된_형식의_암호화된_값_복호화_실패() {
        assertThatThrownBy(() -> memberIdEncryptor.decryptMemberId("invalid-encrypted-value"))
                .isInstanceOf(AuthException.class)
                .extracting("errorCode")
                .isEqualTo(AuthErrorCode.INTERNAL_SERVER_ERROR);
    }

    @Test
    void null_암호화된_값_복호화_실패() {
        assertThatThrownBy(() -> memberIdEncryptor.decryptMemberId(null))
                .isInstanceOf(AuthException.class)
                .extracting("errorCode")
                .isEqualTo(AuthErrorCode.INTERNAL_SERVER_ERROR);
    }
}
