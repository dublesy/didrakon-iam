package com.didrakon.iam.identity.subject

import java.time.Clock
import com.didrakon.iam.identity.group.GroupMemberService
import com.didrakon.iam.identity.group.GroupMemberRepository
import com.didrakon.iam.identity.organization.MembershipService
import com.didrakon.iam.identity.organization.MembershipType
import com.didrakon.iam.identity.organization.SubjectOrganizationRepository
import com.didrakon.iam.identity.event.SubjectStatusChangedEvent
import org.springframework.context.ApplicationEventPublisher
import com.didrakon.iam.common.event.AdminChangeEvent
import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.common.error.NotFoundException
import org.springframework.data.domain.Page
import org.springframework.data.domain.PageRequest
import org.springframework.data.domain.Sort
import org.springframework.data.repository.findByIdOrNull
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.LocalDate

@Service
@Transactional
class UserService(
    private val userRepository: UserRepository,
    private val membershipRepository: SubjectOrganizationRepository,
    private val membershipService: MembershipService,
    private val groupMemberRepository: GroupMemberRepository,
    private val groupMemberService: GroupMemberService,
    private val eventPublisher: ApplicationEventPublisher,
    private val clock: Clock,
) {
    /**
     * 사용자를 만든다. 임직원은 사번이 필요하고, 외부 사용자는 사번 없이 이메일(외부 사용자끼리 고유)과 소속 조직(고객사)이 필요하다.
     * [primaryOrgId] 가 있으면 같은 트랜잭션에서 PRIMARY 소속을 만든다 (조직 역할 규칙도 함께 적용된다)
     */
    fun create(
        empNo: String?,
        name: String,
        email: String?,
        phone: String?,
        hireDate: LocalDate?,
        kind: UserKind = UserKind.EMPLOYEE,
        primaryOrgId: Long? = null,
    ): User {
        val cleanEmpNo = empNo?.trim()?.ifEmpty { null }
        val cleanEmail = email?.trim()?.ifEmpty { null }
        when (kind) {
            UserKind.EMPLOYEE -> {
                if (cleanEmpNo == null) throw BusinessRuleException("임직원은 사번이 필요합니다")
                if (userRepository.findByEmpNo(cleanEmpNo) != null) throw BusinessRuleException("이미 등록된 사번입니다: $cleanEmpNo")
            }
            UserKind.EXTERNAL -> {
                if (cleanEmpNo != null) throw BusinessRuleException("외부 사용자는 사번을 갖지 않습니다")
                if (cleanEmail == null) throw BusinessRuleException("외부 사용자는 이메일이 필요합니다")
                if (primaryOrgId == null) throw BusinessRuleException("외부 사용자는 소속 조직(고객사)이 필요합니다")
                requireUniqueExternalEmail(cleanEmail)
            }
        }
        val user = userRepository.save(User(cleanEmpNo, name, cleanEmail, phone, hireDate, kind))
        if (primaryOrgId != null) membershipService.join(user.requireId(), primaryOrgId, MembershipType.PRIMARY)
        return user
    }

    /**
     * [orgIds] 가 null 이면 전체, 아니면 PRIMARY 소속 조직이 그 안인 사용자만 (조직 단위 관리자)
     */
    @Transactional(readOnly = true)
    fun search(q: String?, kind: UserKind?, orgIds: Set<Long>?, page: Int, size: Int): Page<User> {
        val pageable = PageRequest.of(page.coerceAtLeast(0), size.coerceIn(1, 100), Sort.by("empNo", "name"))
        if (orgIds != null && orgIds.isEmpty()) return Page.empty(pageable)
        return userRepository.search(q?.trim()?.ifEmpty { null }, kind, orgIds != null, orgIds ?: listOf(-1L), pageable)
    }

    /**
     * 연동 시스템 계정 연결용 조회. 사번은 하나에만, 이메일은 여러 사람(임직원과 외부 사용자 등)에 맞을 수 있다.
     * 이메일은 대소문자를 무시하고 비교한다. 결과는 입력 순서대로, 입력값마다 맞은 사용자 목록
     */
    @Transactional(readOnly = true)
    fun lookup(empNos: List<String>, emails: List<String>): Pair<Map<String, List<User>>, Map<String, List<User>>> {
        val cleanEmpNos = empNos.map { it.trim() }.filter { it.isNotEmpty() }.distinct()
        val cleanEmails = emails.map { it.trim() }.filter { it.isNotEmpty() }.distinct()
        val byEmpNo = if (cleanEmpNos.isEmpty()) emptyMap() else userRepository.findByEmpNoIn(cleanEmpNos).groupBy { it.empNo }
        val byEmail = if (cleanEmails.isEmpty()) emptyMap() else {
            userRepository.findByLowerEmailIn(cleanEmails.map { it.lowercase() }).groupBy { it.email?.lowercase() }
        }
        return cleanEmpNos.associateWith { byEmpNo[it].orEmpty() } to cleanEmails.associateWith { byEmail[it.lowercase()].orEmpty() }
    }

    /** 사번은 바꾸지 않는다 (인사 시스템과 맞추는 키). 외부 사용자는 이메일로 식별하므로 비울 수 없다 */
    fun update(subjectId: Long, name: String, email: String?, phone: String?, hireDate: LocalDate?): User {
        val user = get(subjectId)
        if (name.isBlank()) throw BusinessRuleException("이름이 필요합니다")
        val cleanEmail = email?.trim()?.ifEmpty { null }
        if (user.userKind == UserKind.EXTERNAL) {
            if (cleanEmail == null) throw BusinessRuleException("외부 사용자는 이메일이 필요합니다")
            if (!cleanEmail.equals(user.email, ignoreCase = true)) requireUniqueExternalEmail(cleanEmail)
        }
        val before = snapshot(user)
        user.updateProfile(name.trim(), cleanEmail, phone?.trim()?.ifEmpty { null }, hireDate)
        eventPublisher.publishEvent(AdminChangeEvent("USER", subjectId, "UPDATE", before, snapshot(user)))
        return user
    }

    /** 사용 안 함이면 로그인할 수 없다. 화면에서는 ACTIVE·DISABLED 만 다룬다 (잠금·퇴직은 각자의 처리로 바뀐다) */
    fun changeStatus(subjectId: Long, status: SubjectStatus): User {
        if (status != SubjectStatus.ACTIVE && status != SubjectStatus.DISABLED) throw BusinessRuleException("사용·사용 안 함만 바꿀 수 있습니다")
        val user = get(subjectId)
        if (user.status == status) return user
        if (user.status == SubjectStatus.RETIRED) throw BusinessRuleException("퇴직한 사용자는 다시 사용할 수 없습니다")
        val before = snapshot(user)
        user.changeStatus(status)
        eventPublisher.publishEvent(AdminChangeEvent("USER", subjectId, if (status == SubjectStatus.ACTIVE) "ACTIVATE" else "DEACTIVATE", before, snapshot(user)))
        eventPublisher.publishEvent(SubjectStatusChangedEvent(subjectId, status))
        return user
    }

    /**
     * 휴직 (인사 연동). 재직 상태를 LEAVE 로 바꾸고, 사용 중이면 사용 안 함으로 바꾼다.
     * 상태 변경 이벤트로 authn 이 세션·토큰·API 키를 회수한다. 잠김은 그대로 둔다 (이미 로그인할 수 없다)
     */
    fun startLeave(subjectId: Long): User = changeEmployment(subjectId, EmploymentStatus.LEAVE, "LEAVE") {
        if (it == SubjectStatus.ACTIVE) SubjectStatus.DISABLED else it
    }

    /** 복직·재직 확인 (인사 연동). 재직 상태를 EMPLOYED 로, 사용 안 함이면 다시 사용으로 바꾼다. 잠김은 그대로 둔다 */
    fun returnToWork(subjectId: Long): User = changeEmployment(subjectId, EmploymentStatus.EMPLOYED, "RETURN") {
        if (it == SubjectStatus.DISABLED) SubjectStatus.ACTIVE else it
    }

    private fun changeEmployment(subjectId: Long, employment: EmploymentStatus, action: String, nextStatus: (SubjectStatus) -> SubjectStatus): User {
        val user = get(subjectId)
        if (user.status == SubjectStatus.RETIRED) throw BusinessRuleException("퇴직한 사용자는 휴직·복직을 처리할 수 없습니다")
        val status = nextStatus(user.status)
        if (user.employmentStatus == employment && user.status == status) return user
        val before = snapshot(user)
        user.changeEmployment(employment)
        val statusChanged = user.status != status
        user.changeStatus(status)
        eventPublisher.publishEvent(AdminChangeEvent("USER", subjectId, action, before, snapshot(user)))
        if (statusChanged) eventPublisher.publishEvent(SubjectStatusChangedEvent(subjectId, status))
        return user
    }

    /**
     * 퇴사. 퇴사일이 오늘 이후면 예약만 하고 그날 [retireDue] 가 처리한다. 비었거나 오늘·지난 날이면 지금 처리한다.
     * 처리: 소속과 그룹에서 빼고(조직·그룹으로 받은 역할은 동기화가 회수), 퇴직 상태로 바꾼다.
     * 상태 변경 이벤트로 authn 은 세션·토큰·API 키를, authz 는 남은 역할 할당을 회수한다. 처리 뒤에는 되돌릴 수 없다
     */
    fun retire(subjectId: Long, retireDate: LocalDate?): User {
        val user = get(subjectId)
        if (user.status == SubjectStatus.RETIRED) throw BusinessRuleException("이미 퇴사 처리된 사용자입니다")
        val today = LocalDate.now(clock)
        if (retireDate != null && retireDate.isAfter(today)) {
            val before = snapshot(user)
            user.scheduleRetire(retireDate)
            eventPublisher.publishEvent(AdminChangeEvent("USER", subjectId, "SCHEDULE_RETIRE", before, snapshot(user)))
            return user
        }
        return retireNow(user, retireDate ?: today)
    }

    /** 퇴사 예약 취소. 이미 처리된 퇴사는 되돌릴 수 없다 */
    fun cancelScheduledRetire(subjectId: Long): User {
        val user = get(subjectId)
        if (user.status == SubjectStatus.RETIRED) throw BusinessRuleException("이미 퇴사 처리되어 취소할 수 없습니다")
        if (user.retireDate == null) return user
        val before = snapshot(user)
        user.scheduleRetire(null)
        eventPublisher.publishEvent(AdminChangeEvent("USER", subjectId, "CANCEL_RETIRE", before, snapshot(user)))
        return user
    }

    /** 퇴사 예정일이 된 사용자를 처리한다 (만료 스케줄러). 처리한 수 */
    fun retireDue(): Int {
        val due = userRepository.findRetireDue(LocalDate.now(clock))
        due.forEach { retireNow(it, it.retireDate ?: LocalDate.now(clock)) }
        return due.size
    }

    private fun retireNow(user: User, retireDate: LocalDate): User {
        val subjectId = user.requireId()
        val before = snapshot(user)
        membershipRepository.findActiveBySubjectId(subjectId).forEach { membershipService.leave(it.requireId()) }
        groupMemberRepository.findByIdSubjectId(subjectId).forEach { groupMemberService.removeMember(it.id.groupId, subjectId) }
        user.retire(retireDate)
        eventPublisher.publishEvent(AdminChangeEvent("USER", subjectId, "RETIRE", before, snapshot(user)))
        eventPublisher.publishEvent(SubjectStatusChangedEvent(subjectId, SubjectStatus.RETIRED))
        return user
    }

    private fun requireUniqueExternalEmail(email: String) {
        if (userRepository.existsByUserKindAndEmail(UserKind.EXTERNAL, email)) throw BusinessRuleException("이미 등록된 외부 사용자 이메일입니다: $email")
    }

    private fun snapshot(u: User) = mapOf(
        "name" to u.name, "email" to u.email, "phone" to u.phone, "hireDate" to u.hireDate?.toString(),
        "status" to u.status.name, "employmentStatus" to u.employmentStatus.name, "retireDate" to u.retireDate?.toString(),
    )

    @Transactional(readOnly = true)
    fun get(subjectId: Long): User = userRepository.findByIdOrNull(subjectId) ?: throw NotFoundException("사용자", subjectId)
}
