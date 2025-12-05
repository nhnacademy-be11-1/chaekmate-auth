package com.nhnacademy.chaekmateauth.event;

public record LoginSuccessEvent(
        Long memberId,
        String guestId
) {
}
