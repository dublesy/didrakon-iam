package com.didrakon.iam.authn.login

import com.didrakon.iam.authn.credential.LocalAccountService
import com.didrakon.iam.authn.event.AuthenticationEventType
import com.didrakon.iam.authn.event.AuthenticationEventWriter
import com.didrakon.iam.authn.event.AuthenticationResult
import com.didrakon.iam.authn.event.LoggedOutEvent
import com.didrakon.iam.authn.event.LoginFailedEvent
import com.didrakon.iam.authn.event.LoginSucceededEvent
import com.didrakon.iam.authn.mfa.MfaService
import com.didrakon.iam.authn.passkey.PasskeyService
import com.didrakon.iam.authn.session.AuthenticationLevel
import com.didrakon.iam.authn.session.LoginSessionService
import com.didrakon.iam.common.crypto.randomUrlSafe
import com.didrakon.iam.risk.RiskAction
import com.didrakon.iam.risk.RiskContext
import com.didrakon.iam.risk.RiskEngine
import com.didrakon.iam.risk.RiskProperties
import com.didrakon.iam.risk.RiskType
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.context.ApplicationEventPublisher
import org.springframework.context.event.EventListener
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler
import org.springframework.security.web.authentication.WebAuthenticationDetails
import org.springframework.security.web.authentication.logout.LogoutHandler
import org.springframework.stereotype.Component

/** 인증 요소 권한과 세션 속성 이름 */
object AuthFactors {
    const val PASSWORD = "FACTOR_PASSWORD"
    const val TOTP = "FACTOR_TOTP"

    /** 패스키. 기기 소지와 사용자 확인(생체·PIN)을 함께 거쳐 그 자체로 MFA 다 */
    const val WEBAUTHN = "FACTOR_WEBAUTHN"

    /** 2단계 인증을 마친 로그인인가 (TOTP 또는 패스키) */
    fun isMultiFactor(authentication: Authentication): Boolean =
        authentication.authorities.any { it.authority == TOTP || it.authority == WEBAUTHN }

    /** 브라우저 세션에 두는 로그인 세션 키 원문 (DB 에는 hash) */
    const val LOGIN_SESSION_KEY = "iam.loginSessionKey"

    /** 비밀번호는 통과했고 MFA 를 기다리는 중 */
    const val MFA_PENDING = "iam.mfaPending"

    const val MFA_PATH = "/login/mfa"
}

/** 로그인 방법. 패스키는 그 자체로 MFA 라 세션이 바로 MFA 수준이 된다 */
enum class LoginMethod(val level: AuthenticationLevel) {
    PASSWORD(AuthenticationLevel.PASSWORD),
    PASSKEY(AuthenticationLevel.MFA),
}

/** 로그인 처리 결과. 화면 이동은 호출한 쪽(폼 로그인은 redirect, 패스키는 JSON)이 한다 */
sealed interface LoginOutcome {
    /** 위험 때문에 되돌렸다. 로그인 화면의 [url] 로 보낸다 */
    data class Rejected(val url: String) : LoginOutcome

    /** 비밀번호는 통과했고 TOTP 를 기다린다 */
    data object MfaRequired : LoginOutcome

    /** 로그인을 마쳤다. 원래 가려던 곳으로 보낸다 */
    data object Completed : LoginOutcome
}

/**
 * 비밀번호 로그인 성공: [complete] 를 거쳐 MFA 화면·원래 가려던 곳·로그인 화면으로 보낸다.
 *
 * [complete] 는 비밀번호·패스키 로그인이 함께 쓰는 성공 처리다: 위험 평가 → (비밀번호면) 실패 횟수 초기화 → 로그인 세션 기록 → 인증 이벤트.
 * 위험 평가가 DENY 면 로그인을 되돌린다 (실패 횟수는 그대로 둔다).
 * CHALLENGE·APPROVAL 이면 추가 인증(step-up)을 요구한다. 로그인에는 승인 절차가 없어 APPROVAL 도 추가 인증으로 다룬다.
 * - 패스키: 이미 기기 소지와 사용자 확인을 거쳤으므로 추가 인증을 충족한 것으로 보고, 위험 신호만 인증 이벤트(CHALLENGE)로 남긴다.
 * - 비밀번호 + 확인된 MFA 수단: 원래도 MFA 를 거치므로 그대로 MFA 화면으로 보내고, 위험 때문에 요구했음을 인증 이벤트(CHALLENGE)로 남긴다.
 * - 비밀번호 + MFA 수단 없음: 조용히 들여보내지 않고 DENY 처럼 되돌린다 (`iam.risk.block-challenge-without-mfa=false` 면 기록만 하고 들여보낸다).
 * 패스키 로그인은 비밀번호 실패 횟수를 건드리지 않는다 (비밀번호 추측 방어용 횟수다).
 */
@Component
class LoginSuccessHandler(
    private val accountService: LocalAccountService,
    private val sessionService: LoginSessionService,
    private val mfaService: MfaService,
    private val passkeyService: PasskeyService,
    private val riskEngine: RiskEngine,
    private val riskProperties: RiskProperties,
    private val eventWriter: AuthenticationEventWriter,
    private val eventPublisher: ApplicationEventPublisher,
) : AuthenticationSuccessHandler {
    private val delegate = SavedRequestAwareAuthenticationSuccessHandler()

    override fun onAuthenticationSuccess(request: HttpServletRequest, response: HttpServletResponse, authentication: Authentication) {
        when (val outcome = complete(request, authentication, LoginMethod.PASSWORD)) {
            is LoginOutcome.Rejected -> response.sendRedirect(outcome.url)
            LoginOutcome.MfaRequired -> response.sendRedirect(request.contextPath + AuthFactors.MFA_PATH)
            LoginOutcome.Completed -> delegate.onAuthenticationSuccess(request, response, authentication)
        }
    }

    fun complete(request: HttpServletRequest, authentication: Authentication, method: LoginMethod): LoginOutcome {
        val subjectId = authentication.name.toLong()
        val identity = accountService.findLocalIdentity(subjectId) ?: throw IllegalStateException("LOCAL 계정이 없습니다: $subjectId")
        val userAgent = request.getHeader("User-Agent")

        val risk = riskEngine.assess(
            RiskContext(
                subjectId = subjectId,
                type = RiskType.LOGIN,
                ipAddress = request.remoteAddr,
                knownDevice = sessionService.hasUsedDevice(subjectId, userAgent),
                consecutiveFailures = accountService.consecutiveFailures(identity.requireId()),
            ),
        )
        if (risk.decision == RiskAction.DENY) {
            return reject(request, subjectId, identity.id, identity.externalId, userAgent, "RISK_DENIED: ${risk.reason} (${risk.score})", "risk")
        }
        // 2단계 인증 수단이 패스키뿐이면 비밀번호만으로는 들여보내지 않는다. 비밀번호 다음에 받을 인증 앱 코드가 없으므로 패스키로 로그인하게 한다
        if (method == LoginMethod.PASSWORD && !mfaService.hasVerifiedMethod(subjectId) && passkeyService.list(subjectId).isNotEmpty()) {
            return reject(request, subjectId, identity.id, identity.externalId, userAgent, "PASSKEY_REQUIRED", "passkey-required")
        }
        val stepUp = risk.decision == RiskAction.CHALLENGE || risk.decision == RiskAction.APPROVAL
        val needsTotp = method == LoginMethod.PASSWORD && mfaService.hasVerifiedMethod(subjectId)
        if (method == LoginMethod.PASSWORD && stepUp && !needsTotp && riskProperties.blockChallengeWithoutMfa) {
            return reject(
                request, subjectId, identity.id, identity.externalId, userAgent, "RISK_CHALLENGE_NO_MFA: ${risk.reason} (${risk.score})", "challenge",
            )
        }
        if (method == LoginMethod.PASSWORD) accountService.recordSuccess(identity.requireId())

        val sessionKey = randomUrlSafe(32)
        val loginSession = sessionService.open(sessionKey, subjectId, identity.requireId(), method.level, request.remoteAddr, userAgent)
        request.session.setAttribute(AuthFactors.LOGIN_SESSION_KEY, sessionKey)
        eventWriter.write(
            AuthenticationEventType.LOGIN, AuthenticationResult.SUCCESS, subjectId, identity.id, request.remoteAddr, userAgent,
            method.takeIf { it == LoginMethod.PASSKEY }?.name,
        )
        eventPublisher.publishEvent(LoginSucceededEvent(subjectId, identity.requireId(), loginSession.requireId(), request.remoteAddr))

        if (stepUp && (needsTotp || method == LoginMethod.PASSKEY)) {
            eventWriter.write(
                AuthenticationEventType.LOGIN, AuthenticationResult.CHALLENGE, subjectId, identity.id, request.remoteAddr, userAgent,
                "RISK_CHALLENGE: ${risk.reason} (${risk.score})" + if (method == LoginMethod.PASSKEY) " 패스키로 충족" else "",
            )
        }
        if (needsTotp) {
            request.session.setAttribute(AuthFactors.MFA_PENDING, true)
            return LoginOutcome.MfaRequired
        }
        return LoginOutcome.Completed
    }

    /** 위험이나 인증 수단 부족 때문에 로그인을 되돌린다. 인증 자체는 맞았으므로 실패 횟수는 그대로 둔다. [detail] 은 "사유: 설명" 형식 */
    private fun reject(
        request: HttpServletRequest,
        subjectId: Long,
        identityId: Long?,
        loginId: String,
        userAgent: String?,
        detail: String,
        pageParam: String,
    ): LoginOutcome {
        eventWriter.write(AuthenticationEventType.LOGIN, AuthenticationResult.FAILURE, subjectId, identityId, request.remoteAddr, userAgent, detail)
        eventPublisher.publishEvent(LoginFailedEvent(loginId, subjectId, detail.substringBefore(":"), request.remoteAddr))
        SecurityContextHolder.clearContext()
        request.getSession(false)?.invalidate()
        return LoginOutcome.Rejected("${request.contextPath}/login?$pageParam")
    }
}

/** 로그인 실패: 비밀번호 오류만 실패 횟수에 넣고(잠금), 모든 실패를 인증 이벤트로 남긴다 */
@Component
class LoginFailureListener(
    private val accountService: LocalAccountService,
    private val eventWriter: AuthenticationEventWriter,
    private val eventPublisher: ApplicationEventPublisher,
) {
    @EventListener
    fun onFailure(event: AbstractAuthenticationFailureEvent) {
        // 클라이언트 인증·토큰 인증 실패는 사용자 로그인이 아니다
        val authentication = event.authentication as? UsernamePasswordAuthenticationToken ?: return
        val loginId = authentication.name
        if (event.exception is BadCredentialsException) accountService.recordFailure(loginId)

        val identity = accountService.findIdentity(loginId)
        val ipAddress = (authentication.details as? WebAuthenticationDetails)?.remoteAddress
        val reason = event.exception.javaClass.simpleName
        eventWriter.write(
            AuthenticationEventType.FAILED_LOGIN, AuthenticationResult.FAILURE, identity?.subjectId, identity?.id, ipAddress, null, reason,
        )
        eventPublisher.publishEvent(LoginFailedEvent(loginId, identity?.subjectId, reason, ipAddress))
    }
}

/** 로그아웃: 로그인 세션을 닫고 인증 이벤트를 남긴다. HTTP 세션 무효화보다 먼저 실행된다 */
@Component
class LoginSessionLogoutHandler(
    private val sessionService: LoginSessionService,
    private val eventWriter: AuthenticationEventWriter,
    private val eventPublisher: ApplicationEventPublisher,
) : LogoutHandler {
    override fun logout(request: HttpServletRequest, response: HttpServletResponse, authentication: Authentication?) {
        val sessionKey = request.getSession(false)?.getAttribute(AuthFactors.LOGIN_SESSION_KEY) as? String ?: return
        val closed = sessionService.close(sessionKey)
        val subjectId = authentication?.name?.toLongOrNull() ?: closed?.subjectId ?: return
        eventWriter.write(
            AuthenticationEventType.LOGOUT, AuthenticationResult.SUCCESS, subjectId, closed?.identityId, request.remoteAddr,
            request.getHeader("User-Agent"),
        )
        eventPublisher.publishEvent(LoggedOutEvent(subjectId, closed?.id))
    }
}
