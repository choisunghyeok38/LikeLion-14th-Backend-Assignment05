package com.likelion.likelioncrud.kakao.api.dto;


import com.likelion.likelioncrud.auth.api.dto.response.LoginResponseDto;

import com.likelion.likelioncrud.common.response.code.SuccessCode;
import com.likelion.likelioncrud.common.template.ApiResTemplate;
import com.likelion.likelioncrud.kakao.application.KakaoAuthService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;



@RestController
@RequiredArgsConstructor
@RequestMapping("/auth/kakao")
@Tag(name = "카카오 로그인 API", description = "카카오 소셜 로그인 API")

public class KakaOAuthController {

    private  final KakaoAuthService kakaoAuthService;

    @GetMapping("/callback")
    public ApiResTemplate<LoginResponseDto> kakaoCallback(@RequestParam("code") String code) {
        LoginResponseDto response = kakaoAuthService.kakaoLogin(code);
        return ApiResTemplate.successResponse(SuccessCode.LOGIN_SUCCESS, response);
    }
}
