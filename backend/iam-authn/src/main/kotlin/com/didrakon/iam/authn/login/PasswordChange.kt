package com.didrakon.iam.authn.login

import com.didrakon.iam.authn.credential.LocalAccountService
import com.didrakon.iam.common.error.BusinessRuleException
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.CredentialsExpiredException
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.CredentialsContainer
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler
import org.springframework.stereotype.Component
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import java.time.Clock
import java.time.Duration
import java.time.Instant

/** 비밀번호 변경이 필요한 계정. 비밀번호를 맞혔거나(만료·초기화) 인증 앱 코드를 맞힌 뒤(셀프 재설정)에만 세션에 둔다 */
private data class PendingPasswordChange(val identityId: Long, val loginId: String, val since: Instant) : java.io.Serializable

private const val PENDING = "iam.passwordChangePending"
internal const val CHANGE_PATH = "/login/password"
private val PENDING_TTL: Duration = Duration.ofMinutes(10)

/** 본인 확인을 마친 계정을 비밀번호 변경 화면으로 보낼 수 있게 세션에 표시한다 */
internal fun allowPasswordChange(request: HttpServletRequest, identityId: Long, loginId: String, now: Instant) {
    request.getSession(true).setAttribute(PENDING, PendingPasswordChange(identityId, loginId, now))
}

/**
 * 로그인 실패 처리. 비밀번호가 만료되었거나 관리자가 초기화한 계정(CredentialsExpiredException)은 변경 화면으로 보낸다.
 * Spring 은 비밀번호를 확인한 다음에 이 예외를 던지므로, 여기 온 사용자는 현재 비밀번호를 맞힌 사람이다.
 * 그 밖의 실패는 기존처럼 /login?error
 */
@Component
class LoginFailureHandler(
    private val accountService: LocalAccountService,
    private val clock: Clock,
) : SimpleUrlAuthenticationFailureHandler("/login?error") {
    override fun onAuthenticationFailure(request: HttpServletRequest, response: HttpServletResponse, exception: AuthenticationException) {
        // 부모가 이 예외를 세션(DB 에 저장된다)에 두어 로그인 화면이 문구를 고른다. 예외에 달린 로그인 요청에서 입력한 비밀번호를 지운다
        (exception.authenticationRequest as? CredentialsContainer)?.eraseCredentials()
        val loginId = request.getParameter("username")
        val identity = loginId?.let { accountService.findIdentity(it) }
        if (exception is CredentialsExpiredException && identity != null) {
            // 로그인 전 세션에 변경 권한을 붙이므로 ID 를 바꾼다 (심어 둔 세션 ID 로 남의 비밀번호를 정하지 못하게)
            request.getSession(false)?.let { request.changeSessionId() }
            allowPasswordChange(request, identity.requireId(), loginId, clock.instant())
            response.sendRedirect(request.contextPath + CHANGE_PATH)
            return
        }
        super.onAuthenticationFailure(request, response, exception)
    }
}

/** 로그인 전에 비밀번호를 바꾸는 화면. 바꾸면 새 비밀번호로 다시 로그인한다 */
@Controller
class PasswordChangeController(
    private val accountService: LocalAccountService,
    private val clock: Clock,
) {
    @GetMapping(CHANGE_PATH)
    fun form(request: HttpServletRequest, model: Model): String {
        val pending = pending(request) ?: return "redirect:/login"
        model.addAttribute("loginId", pending.loginId)
        return "password"
    }

    @PostMapping(CHANGE_PATH)
    fun change(
        request: HttpServletRequest,
        model: Model,
        @RequestParam newPassword: String,
        @RequestParam confirmPassword: String,
    ): String {
        val pending = pending(request) ?: return "redirect:/login"
        model.addAttribute("loginId", pending.loginId)
        if (newPassword != confirmPassword) {
            model.addAttribute("error", "두 비밀번호가 다릅니다")
            return "password"
        }
        try {
            accountService.changePassword(pending.identityId, newPassword)
        } catch (e: BusinessRuleException) {
            model.addAttribute("error", e.message)
            return "password"
        }
        request.session.removeAttribute(PENDING)
        return "redirect:/login?changed"
    }

    private fun pending(request: HttpServletRequest): PendingPasswordChange? {
        val session = request.getSession(false) ?: return null
        val pending = session.getAttribute(PENDING) as? PendingPasswordChange ?: return null
        if (pending.since.plus(PENDING_TTL).isBefore(clock.instant())) {
            session.removeAttribute(PENDING)
            return null
        }
        return pending
    }
}
