package com.didrakon.iam.authn.login

import com.didrakon.iam.authn.credential.LocalAccountService
import com.didrakon.iam.authn.event.AuthenticationEventType
import com.didrakon.iam.authn.event.AuthenticationEventWriter
import com.didrakon.iam.authn.event.AuthenticationResult
import com.didrakon.iam.authn.event.PasswordResetEvent
import com.didrakon.iam.authn.mfa.MfaService
import com.didrakon.iam.identity.provider.Identity
import com.didrakon.iam.identity.subject.SubjectRepository
import com.didrakon.iam.identity.subject.SubjectStatus
import jakarta.servlet.http.HttpServletRequest
import org.springframework.context.ApplicationEventPublisher
import org.springframework.data.repository.findByIdOrNull
import org.springframework.stereotype.Component
import org.springframework.stereotype.Controller
import org.springframework.transaction.annotation.Isolation
import org.springframework.transaction.annotation.Transactional
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import java.time.Clock
import java.time.Duration

internal const val FORGOT_PATH = "/login/forgot"

/**
 * 셀프 비밀번호 재설정. 메일·문자 수단이 없으므로 이미 등록·확인한 인증 앱(TOTP) 코드로 본인을 확인한다.
 * 잠긴 계정도 쓸 수 있고(본인 잠금 해제), 새 비밀번호를 정하면 잠금과 실패 횟수가 풀린다.
 * 사용자 상태가 ACTIVE 가 아니면(사용 중지·잠김·퇴사) 통과시키지 않는다.
 *
 * 시도 제한은 로그인 잠금과 따로 센다: 계정마다 최근 1시간에 실패 5번이면 코드가 맞아도 거부한다.
 * 실패는 AUTHENTICATION_EVENT(PASSWORD_CHANGE, FAILURE, [FAILED])로 남기고 그 행을 센다.
 * 제한에 걸린 시도는 [LIMITED] 로 남겨 세지 않는다 (마지막 실패 1시간 뒤 풀린다).
 * 같은 계정에 대한 시도는 MFA 수단을 잠가 한 번에 하나씩 처리한다. 동시에 보내 모두 같은 실패 횟수를 읽고 통과하는 일을 막는다.
 */
@Component
class PasswordResetService(
    private val accountService: LocalAccountService,
    private val subjectRepository: SubjectRepository,
    private val mfaService: MfaService,
    private val eventWriter: AuthenticationEventWriter,
    private val eventPublisher: ApplicationEventPublisher,
    private val clock: Clock,
) {
    /** 본인 확인에 성공하면 그 계정, 아니면 null. 실패 이유는 밖으로 구분하지 않는다 (계정 존재 여부가 드러나지 않게) */
    // 잠근 뒤 센 실패 횟수가 앞 시도의 기록까지 보도록 READ COMMITTED 로 읽는다 (REPEATABLE READ 면 처음 읽은 시점의 횟수에 머문다)
    @Transactional(isolation = Isolation.READ_COMMITTED)
    fun verify(loginId: String, code: String, ipAddress: String?, userAgent: String?): Identity? {
        val identity = accountService.findIdentity(loginId)
        val subjectId = identity?.subjectId
        subjectId?.let(mfaService::lock)
        val reason = when {
            subjectId == null -> FAILED
            recentFailures(subjectId) >= MAX_FAILURES -> LIMITED
            subjectRepository.findByIdOrNull(subjectId)?.status != SubjectStatus.ACTIVE -> FAILED
            // 확인을 마친 TOTP 가 없으면 false. 성공한 코드는 재사용할 수 없다
            !mfaService.verify(subjectId, code) -> FAILED
            else -> OK
        }
        val success = reason == OK
        eventWriter.write(
            AuthenticationEventType.PASSWORD_CHANGE, if (success) AuthenticationResult.SUCCESS else AuthenticationResult.FAILURE,
            subjectId, identity?.id, ipAddress, userAgent, reason,
        )
        eventPublisher.publishEvent(PasswordResetEvent(loginId, subjectId, success, reason, ipAddress))
        return identity.takeIf { success }
    }

    private fun recentFailures(subjectId: Long): Int = eventWriter.countSince(
        subjectId, AuthenticationEventType.PASSWORD_CHANGE, AuthenticationResult.FAILURE, FAILED, clock.instant().minus(WINDOW),
    )

    companion object {
        const val OK = "PASSWORD_RESET_OK"
        const val FAILED = "PASSWORD_RESET_FAILED"
        const val LIMITED = "PASSWORD_RESET_LIMITED"
        const val MAX_FAILURES = 5
        val WINDOW: Duration = Duration.ofHours(1)
    }
}

/** "비밀번호를 잊으셨나요?" 화면. 확인되면 기존 비밀번호 변경 화면(/login/password)으로 보낸다 */
@Controller
class PasswordResetController(
    private val resetService: PasswordResetService,
    private val clock: Clock,
) {
    @GetMapping(FORGOT_PATH)
    fun form(request: HttpServletRequest, model: Model): String {
        if ("error" in request.parameterMap) model.addAttribute("error", "로그인 ID 또는 인증 코드가 맞지 않습니다. 인증 앱을 등록하지 않았다면 관리자에게 문의하세요.")
        return "forgot"
    }

    @PostMapping(FORGOT_PATH)
    fun verify(request: HttpServletRequest, @RequestParam loginId: String, @RequestParam code: String): String {
        val identity = resetService.verify(loginId, code, request.remoteAddr, request.getHeader("User-Agent"))
            ?: return "redirect:$FORGOT_PATH?error"
        // 본인 확인으로 권한이 바뀌므로 세션 ID 를 새로 받는다 (세션 고정 방지)
        request.getSession(true)
        request.changeSessionId()
        allowPasswordChange(request, identity.requireId(), identity.externalId, clock.instant())
        return "redirect:$CHANGE_PATH"
    }
}
