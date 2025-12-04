package com.nhnacademy.chaekmateauth.dto.response;

import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@SuppressWarnings("NonAsciiCharacters")
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class PaycoMemberInfoResponseTest {

    @Test
    void PaycoMemberInfoResponse_생성_성공() {
        PaycoMemberInfoResponse.Member member = new PaycoMemberInfoResponse.Member(
                "payco123", "테스트", "test@test.com", "010-1234-5678");
        PaycoMemberInfoResponse.Data data = new PaycoMemberInfoResponse.Data(member);
        PaycoMemberInfoResponse.Header header = new PaycoMemberInfoResponse.Header(
                true, 200, "success");

        PaycoMemberInfoResponse response = new PaycoMemberInfoResponse(header, data);

        assertThat(response.header().isSuccessful()).isTrue();
        assertThat(response.header().resultCode()).isEqualTo(200);
        assertThat(response.header().resultMessage()).isEqualTo("success");
        assertThat(response.data().member().idNo()).isEqualTo("payco123");
        assertThat(response.data().member().name()).isEqualTo("테스트");
        assertThat(response.data().member().email()).isEqualTo("test@test.com");
        assertThat(response.data().member().mobile()).isEqualTo("010-1234-5678");
    }

    @Test
    void PaycoMemberInfoResponse_null_값_처리() {
        PaycoMemberInfoResponse.Member member = new PaycoMemberInfoResponse.Member(
                "payco123", null, null, null);
        PaycoMemberInfoResponse.Data data = new PaycoMemberInfoResponse.Data(member);
        PaycoMemberInfoResponse.Header header = new PaycoMemberInfoResponse.Header(
                false, 400, "error");

        PaycoMemberInfoResponse response = new PaycoMemberInfoResponse(header, data);

        assertThat(response.header().isSuccessful()).isFalse();
        assertThat(response.data().member().idNo()).isEqualTo("payco123");
        assertThat(response.data().member().name()).isNull();
        assertThat(response.data().member().email()).isNull();
        assertThat(response.data().member().mobile()).isNull();
    }
}
