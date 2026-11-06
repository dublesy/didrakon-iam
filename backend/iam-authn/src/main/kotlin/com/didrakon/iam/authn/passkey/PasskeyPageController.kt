package com.didrakon.iam.authn.passkey

import com.didrakon.iam.authn.login.AuthFactors
import com.didrakon.iam.authn.mfa.MfaService
import com.didrakon.iam.common.error.NotFoundException
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.core.Authentication
import org.springframework.security.web.savedrequest.HttpSessionRequestCache
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import java.time.Clock
import java.time.Instant
import java.time.format.DateTimeFormatter

/** 화면에 그릴 패스키 한 줄 */
data class PasskeyRow(val credentialId: String, val label: String, val createdAt: String, val lastUsedAt: String)

/**
 * IdP 의 패스키 관리 화면. 등록은 이 화면의 스크립트가 Spring 의 /webauthn/register 로 한다.
 * 2단계 인증(TOTP 또는 패스키)을 거친 로그인에서만 등록·삭제할 수 있다.
 * - 비밀번호만으로 로그인했고 인증 앱이 있으면: 인증 앱 코드를 받고 이 화면으로 돌아온다.
 * - 인증 앱도 없으면: 먼저 인증 앱을 등록하라고 안내한다 (비밀번호만으로는 패스키를 등록할 수 없다).
 */
@Controller
class PasskeyPageController(
    private val passkeyService: PasskeyService,
    private val mfaService: MfaService,
    clock: Clock,
) {
    private val requestCache = HttpSessionRequestCache()
    private val timeFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(clock.zone)

    @GetMapping(PATH)
    fun page(request: HttpServletRequest, response: HttpServletResponse, authentication: Authentication, model: Model): String {
        val subjectId = authentication.name.toLong()
        val multiFactor = AuthFactors.isMultiFactor(authentication)
        if (!multiFactor && mfaService.hasVerifiedMethod(subjectId)) {
            // 이 화면이 인증 앱 코드 확인 뒤 돌아올 곳이다
            requestCache.saveRequest(request, response)
            request.session.setAttribute(AuthFactors.MFA_PENDING, true)
            return "redirect:${AuthFactors.MFA_PATH}"
        }
        val params = request.parameterMap.keys
        model.addAttribute("canManage", multiFactor)
        model.addAttribute("passkeys", if (multiFactor) passkeyService.list(subjectId).map(::row) else emptyList())
        model.addAttribute(
            "info",
            when {
                "added" in params -> "패스키를 등록했습니다. 다음부터 로그인 화면에서 패스키로 로그인할 수 있습니다."
                "removed" in params -> "패스키를 삭제했습니다."
                else -> null
            },
        )
        return "passkeys"
    }

    @PostMapping("$PATH/{credentialId}/delete")
    fun delete(authentication: Authentication, @PathVariable credentialId: String): String {
        if (!AuthFactors.isMultiFactor(authentication)) throw AccessDeniedException("2단계 인증을 거친 로그인이 필요합니다")
        return try {
            passkeyService.remove(authentication.name.toLong(), credentialId)
            "redirect:$PATH?removed"
        } catch (e: NotFoundException) {
            // 이미 지웠으면(두 번 누름 등) 목록으로 돌아간다
            "redirect:$PATH"
        }
    }

    private fun row(passkey: Passkey) = PasskeyRow(passkey.credentialId, passkey.label, format(passkey.createdAt), format(passkey.lastUsedAt))

    private fun format(instant: Instant?): String = instant?.let(timeFormat::format) ?: "-"

    companion object {
        const val PATH = "/account/passkeys"
    }
}
