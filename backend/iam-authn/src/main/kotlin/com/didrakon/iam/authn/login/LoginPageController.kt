package com.didrakon.iam.authn.login

import com.didrakon.iam.authn.config.AuthnProperties
import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.authentication.AccountExpiredException
import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.authentication.CredentialsExpiredException
import org.springframework.security.authentication.DisabledException
import org.springframework.security.authentication.LockedException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.WebAttributes
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping

/**
 * 로그인 화면. 실패 이유는 계정 존재 여부가 드러나지 않는 수준으로만 구분한다
 * (없는 ID 와 틀린 비밀번호는 같은 문구).
 * 이미 로그인을 마친 사람이 주소로 직접 열면 폼 대신 IAM 홈으로 보낸다. 안내 문구가 있는 요청(?error, ?logout 등)과
 * 2단계 인증을 기다리는 중에는 그대로 폼을 보인다.
 */
@Controller
class LoginPageController(private val properties: AuthnProperties) {
    @GetMapping("/login")
    fun login(request: HttpServletRequest, model: Model): String {
        val params = request.parameterMap.keys
        if (params.isEmpty() && isSignedIn(request)) return "redirect:/"
        when {
            "locked" in params -> model.addAttribute("error", lockedMessage())
            "risk" in params -> model.addAttribute("error", "평소와 다른 위험한 로그인으로 판단되어 막았습니다. 계속 막히면 관리자에게 문의하세요.")
            "challenge" in params -> model.addAttribute(
                "error", "평소와 다른 로그인이라 추가 인증이 필요합니다. 2단계 인증을 등록한 뒤 다시 시도하거나 관리자에게 문의하세요.",
            )
            "passkey-required" in params -> model.addAttribute(
                "error", "이 계정은 패스키로 로그인합니다. 아래 '패스키로 로그인'을 누르세요. 패스키를 쓸 수 없으면 관리자에게 초기화를 요청하세요.",
            )
            "passkey" in params -> model.addAttribute("error", "패스키로 로그인하지 못했습니다. 이 계정에 등록한 패스키인지 확인하고 다시 시도하세요.")
            "unavailable" in params -> model.addAttribute("error", "사용할 수 없거나 잠긴 계정입니다. 잠긴 계정은 비밀번호 재설정으로 풀거나 관리자에게 문의하세요.")
            "error" in params -> model.addAttribute("error", failureMessage(request))
            "logout" in params -> model.addAttribute("info", "로그아웃했습니다.")
            "changed" in params -> model.addAttribute("info", "비밀번호를 바꿨습니다. 새 비밀번호로 로그인하세요.")
        }
        return "login"
    }

    private fun isSignedIn(request: HttpServletRequest): Boolean {
        val authentication = SecurityContextHolder.getContext().authentication
        if (authentication == null || !authentication.isAuthenticated || authentication is AnonymousAuthenticationToken) return false
        val session = request.getSession(false) ?: return false
        return session.getAttribute(AuthFactors.MFA_PENDING) == null && session.getAttribute(AuthFactors.LOGIN_SESSION_KEY) != null
    }

    private fun failureMessage(request: HttpServletRequest): String =
        when (request.getSession(false)?.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION)) {
            is LockedException -> lockedMessage()
            is CredentialsExpiredException -> "비밀번호 사용 기간이 지났습니다. 관리자에게 초기화를 요청하세요."
            is DisabledException, is AccountExpiredException -> "사용할 수 없거나 잠긴 계정입니다. 잠긴 계정은 비밀번호 재설정으로 풀거나 관리자에게 문의하세요."
            else -> "로그인 ID 또는 비밀번호가 맞지 않습니다."
        }

    private fun lockedMessage() =
        "로그인에 여러 번 실패해 계정이 잠겼습니다. ${properties.lockDuration.toMinutes()}분 뒤 다시 시도하거나 관리자에게 문의하세요."
}
