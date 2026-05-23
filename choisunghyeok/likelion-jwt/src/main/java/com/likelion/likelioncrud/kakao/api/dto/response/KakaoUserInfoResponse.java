package com.likelion.likelioncrud.kakao.api.dto.response;

import com.fasterxml.jackson.annotation.JsonProperty;

public record KakaoUserInfoResponse(

        Long id,

        @JsonProperty("properties")
        Properties properties,

        @JsonProperty("kakao_account")
        KakaoAccount kakaoAccount
) {

    public record Properties(
            String nickname
    ){
    }

    public record KakaoAccount(
            String email
    ){
    }

    public String getNickname(){
        if (properties == null || properties.nickname() == null){
            return "카카오사용자";
        }

        return properties.nickname();
    }

    public String getEmail() {
        /*
        *TODO
        * 카카오 동의항목에서 이메일 권한을 설정한 뒤,
        * kakaoAccount.email()을 반환하도록 수정
         */
        if (kakaoAccount == null || kakaoAccount.email() == null){
            // 이메일이 없는 경우 사용할 기본값
            return "test@kakao.com";
        }
        // 정상적으로 이메일이 존재하면 해당 값 반환
        return kakaoAccount.email();
    }
}
