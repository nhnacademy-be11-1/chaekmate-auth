package com.nhnacademy.chaekmateauth.dto.response;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public record PaycoMemberInfoResponse(
        Header header,
        Data data
) {
    public record Header(
            @JsonProperty("isSuccessful") boolean isSuccessful,
            @JsonProperty("resultCode") int resultCode,
            @JsonProperty("resultMessage") String resultMessage
    ) {
    }

    public record Data(
            Member member
    ) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Member(
            @JsonProperty("idNo") String idNo,  // PAYCO ID (필수)
            String name,         // 이름 (선택, null 가능)
            String email,        // 이메일 (선택, null 가능)
            String mobile        // 전화번호 (선택, null 가능)
    ) {
    }
}
