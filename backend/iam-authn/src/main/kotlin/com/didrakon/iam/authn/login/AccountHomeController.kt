package com.didrakon.iam.authn.login

import com.didrakon.iam.authn.client.ClientType
import com.didrakon.iam.authn.client.SsoClientRepository
import com.didrakon.iam.authn.config.AuthnProperties
import com.didrakon.iam.authn.event.AuthenticationEventReader
import com.didrakon.iam.authn.event.AuthenticationEventType
import com.didrakon.iam.authn.event.AuthenticationResult
import com.didrakon.iam.authn.event.LoggedOutEvent
import com.didrakon.iam.authn.event.RecentAuthenticationEvent
import com.didrakon.iam.authn.session.LoginSession
import com.didrakon.iam.authn.session.LoginSessionService
import com.didrakon.iam.common.crypto.sha256Hex
import com.didrakon.iam.identity.subject.SubjectRepository
import jakarta.servlet.http.HttpServletRequest
import org.springframework.context.ApplicationEventPublisher
import org.springframework.data.repository.findByIdOrNull
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import java.time.Clock
import java.time.Instant
import java.time.format.DateTimeFormatter

/** 앱 런처 한 칸 */
data class AppLink(val name: String, val url: String, val initial: String)

/** 로그인된 기기 한 줄 */
data class SessionRow(val device: String, val ipAddress: String, val loginAt: String, val lastActivityAt: String, val current: Boolean)

/** 최근 보안 활동 한 줄 */
data class ActivityRow(val at: String, val label: String, val ok: Boolean, val device: String, val ipAddress: String)

/**
 * IAM 홈 (내 계정). 다른 시스템을 거치지 않고 IAM 에 바로 로그인했을 때 도착하는 곳이다.
 * - 내 앱: 앱 시작 주소(home_url)를 둔 켜진 클라이언트 바로가기 (접근 권한은 각 시스템이 판단한다)
 * - 계정 보안 바로가기: 패스키(이 서버), 내 정보·비밀번호·2단계 인증(관리 콘솔)
 * - 로그인된 기기와 다른 기기 로그아웃, 최근 로그인 기록
 */
@Controller
class AccountHomeController(
    private val ssoClientRepository: SsoClientRepository,
    private val subjectRepository: SubjectRepository,
    private val sessionService: LoginSessionService,
    private val eventReader: AuthenticationEventReader,
    private val eventPublisher: ApplicationEventPublisher,
    private val properties: AuthnProperties,
    clock: Clock,
) {
    private val timeFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(clock.zone)

    @GetMapping("/")
    fun home(request: HttpServletRequest, authentication: Authentication, model: Model): String {
        val subjectId = authentication.name.toLong()
        val currentKeyHash = (request.getSession(false)?.getAttribute(AuthFactors.LOGIN_SESSION_KEY) as? String)?.let(::sha256Hex)
        model.addAttribute("name", subjectRepository.findByIdOrNull(subjectId)?.subjectName ?: "")
        model.addAttribute("consoleUrl", properties.consoleUrl.ifBlank { "http://localhost:3000" }.trimEnd('/'))
        model.addAttribute("apps", apps())
        model.addAttribute(
            "sessions",
            sessionService.activeSessions(subjectId).sortedByDescending { it.loginAt }.map { sessionRow(it, currentKeyHash) },
        )
        model.addAttribute("activities", eventReader.recent(subjectId, RECENT_ACTIVITIES).map(::activityRow))
        model.addAttribute(
            "info",
            request.getParameter("signedOut")?.toIntOrNull()?.let { if (it > 0) "다른 기기 ${it}곳에서 로그아웃했습니다." else "다른 기기에서 로그인된 곳이 없습니다." },
        )
        return "home"
    }

    /** 지금 이 브라우저만 남기고 내 다른 로그인 세션을 모두 끝낸다 (그 세션에서 받은 토큰도 회수, 연동 시스템에는 back-channel 로그아웃) */
    @PostMapping("/account/sessions/revoke-others")
    fun revokeOthers(request: HttpServletRequest, authentication: Authentication): String {
        val subjectId = authentication.name.toLong()
        val currentKey = request.getSession(false)?.getAttribute(AuthFactors.LOGIN_SESSION_KEY) as? String ?: return "redirect:/"
        val ended = sessionService.revokeOthers(subjectId, currentKey)
        ended.forEach { eventPublisher.publishEvent(LoggedOutEvent(subjectId, it.id)) }
        return "redirect:/?signedOut=${ended.size}"
    }

    private fun apps(): List<AppLink> = ssoClientRepository.findAll()
        .filter { it.isActive && (it.clientType == ClientType.WEB || it.clientType == ClientType.MOBILE) }
        .mapNotNull { c -> c.homeUrl?.let { AppLink(c.clientName, it, c.clientName.trim().take(1).uppercase()) } }
        .sortedBy { it.name }

    private fun sessionRow(s: LoginSession, currentKeyHash: String?) = SessionRow(
        device = deviceOf(s.userAgent),
        ipAddress = ipOf(s.ipAddress),
        loginAt = time(s.loginAt),
        lastActivityAt = time(s.lastActivityAt),
        current = s.sessionKeyHash == currentKeyHash,
    )

    private fun activityRow(e: RecentAuthenticationEvent): ActivityRow {
        val passkey = e.failureReason?.startsWith("PASSKEY") == true
        val label = when (e.type) {
            AuthenticationEventType.LOGIN -> if (e.result == AuthenticationResult.SUCCESS) (if (passkey) "패스키로 로그인" else "로그인") else "로그인 추가 인증 요구"
            AuthenticationEventType.FAILED_LOGIN -> if (passkey) "패스키 로그인 실패" else "로그인 실패"
            AuthenticationEventType.LOGOUT -> "로그아웃"
            AuthenticationEventType.MFA -> if (e.result == AuthenticationResult.SUCCESS) "2단계 인증" else "2단계 인증 실패"
            AuthenticationEventType.PASSWORD_CHANGE -> if (e.result == AuthenticationResult.SUCCESS) "비밀번호 변경" else "비밀번호 변경 실패"
        }
        val ok = e.result == AuthenticationResult.SUCCESS && e.type != AuthenticationEventType.FAILED_LOGIN
        return ActivityRow(time(e.at), label, ok, deviceOf(e.userAgent), ipOf(e.ipAddress))
    }

    private fun time(at: Instant) = timeFormat.format(at)

    companion object {
        const val RECENT_ACTIVITIES = 10

        /** 루프백(같은 컴퓨터에서 접속)은 읽기 어려운 IPv6 표기 대신 말로 보여 준다 */
        fun ipOf(ip: String?): String = when (ip) {
            null, "" -> "-"
            "127.0.0.1", "::1", "0:0:0:0:0:0:0:1" -> "이 컴퓨터"
            else -> ip
        }

        /** User-Agent 를 "Chrome · macOS" 처럼 줄인다. 모르면 "알 수 없는 기기" */
        fun deviceOf(userAgent: String?): String {
            val ua = userAgent ?: return "알 수 없는 기기"
            val browser = when {
                "Edg/" in ua -> "Edge"
                "Whale/" in ua -> "Whale"
                "SamsungBrowser/" in ua -> "Samsung Internet"
                "Chrome/" in ua -> "Chrome"
                "Firefox/" in ua -> "Firefox"
                "Safari/" in ua -> "Safari"
                else -> null
            }
            val os = when {
                "iPhone" in ua || "iPad" in ua -> "iOS"
                "Android" in ua -> "Android"
                "Mac OS X" in ua || "Macintosh" in ua -> "macOS"
                "Windows" in ua -> "Windows"
                "Linux" in ua -> "Linux"
                else -> null
            }
            return listOfNotNull(browser, os).joinToString(" · ").ifEmpty { "알 수 없는 기기" }
        }
    }
}
