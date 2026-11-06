package com.didrakon.iam.authn.login

import com.didrakon.iam.authn.credential.LocalAccountService
import com.didrakon.iam.authn.event.AuthenticationEventType
import com.didrakon.iam.authn.event.AuthenticationEventWriter
import com.didrakon.iam.authn.event.AuthenticationResult
import com.didrakon.iam.authn.event.MfaVerifiedEvent
import com.didrakon.iam.authn.mfa.MfaService
import com.didrakon.iam.authn.session.LoginSessionService
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.context.ApplicationEventPublisher
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler
import org.springframework.security.web.context.HttpSessionSecurityContextRepository
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam

/** 비밀번호 다음 단계의 TOTP 입력 화면. 성공하면 인증에 TOTP 요소를 더하고 원래 가려던 곳으로 보낸다 */
@Controller
class MfaLoginController(
    private val mfaService: MfaService,
    private val accountService: LocalAccountService,
    private val sessionService: LoginSessionService,
    private val eventWriter: AuthenticationEventWriter,
    private val eventPublisher: ApplicationEventPublisher,
) {
    private val contextRepository = HttpSessionSecurityContextRepository()
    private val successHandler = SavedRequestAwareAuthenticationSuccessHandler()

    @GetMapping(AuthFactors.MFA_PATH)
    fun form(@RequestParam(required = false) error: String?, model: Model): String {
        model.addAttribute("error", error != null)
        return "mfa"
    }

    @PostMapping(AuthFactors.MFA_PATH)
    fun verify(request: HttpServletRequest, response: HttpServletResponse, @RequestParam code: String) {
        val authentication = SecurityContextHolder.getContext().authentication ?: throw IllegalStateException("로그인 상태가 아닙니다")
        val subjectId = authentication.name.toLong()
        val success = mfaService.verify(subjectId, code)
        eventWriter.write(
            AuthenticationEventType.MFA, if (success) AuthenticationResult.SUCCESS else AuthenticationResult.FAILURE, subjectId,
            ipAddress = request.remoteAddr, userAgent = request.getHeader("User-Agent"),
        )
        eventPublisher.publishEvent(MfaVerifiedEvent(subjectId, success))
        if (!success) {
            if (accountService.recordMfaFailure(subjectId)) {
                // 코드 추측으로 잠겼으면 이 로그인 시도를 끝낸다
                (request.session.getAttribute(AuthFactors.LOGIN_SESSION_KEY) as? String)?.let(sessionService::close)
                request.session.invalidate()
                SecurityContextHolder.clearContext()
                response.sendRedirect(request.contextPath + "/login?locked")
                return
            }
            response.sendRedirect(request.contextPath + AuthFactors.MFA_PATH + "?error")
            return
        }
        accountService.findLocalIdentity(subjectId)?.let { accountService.recordSuccess(it.requireId()) }

        val upgraded = UsernamePasswordAuthenticationToken.authenticated(
            authentication.principal ?: throw IllegalStateException("principal 이 없습니다"), null, authentication.authorities + SimpleGrantedAuthority(AuthFactors.TOTP),
        ).apply { details = authentication.details }
        val context = SecurityContextHolder.createEmptyContext().apply { this.authentication = upgraded }
        SecurityContextHolder.setContext(context)
        contextRepository.saveContext(context, request, response)

        val session = request.session
        session.removeAttribute(AuthFactors.MFA_PENDING)
        (session.getAttribute(AuthFactors.LOGIN_SESSION_KEY) as? String)?.let(sessionService::upgradeToMfa)
        successHandler.onAuthenticationSuccess(request, response, upgraded)
    }
}
