package com.nhnacademy.chaekmateauth.dto.response;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public record PaycoTokenResponse(
        @JsonProperty("access_token") String accessToken  // PAYCO Access Token (필수)
) {
}