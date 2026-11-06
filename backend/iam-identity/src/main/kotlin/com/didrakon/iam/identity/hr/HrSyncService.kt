package com.didrakon.iam.identity.hr

import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.common.error.IamException
import com.didrakon.iam.identity.organization.MembershipService
import com.didrakon.iam.identity.organization.MembershipType
import com.didrakon.iam.identity.organization.Organization
import com.didrakon.iam.identity.organization.OrganizationRepository
import com.didrakon.iam.identity.organization.SubjectOrganizationRepository
import com.didrakon.iam.identity.subject.EmploymentStatus
import com.didrakon.iam.identity.subject.SubjectStatus
import com.didrakon.iam.identity.subject.User
import com.didrakon.iam.identity.subject.UserRepository
import com.didrakon.iam.identity.subject.UserKind
import com.didrakon.iam.identity.subject.UserService
import org.slf4j.LoggerFactory
import org.springframework.dao.DataIntegrityViolationException
import org.springframework.stereotype.Service
import org.springframework.transaction.PlatformTransactionManager
import org.springframework.transaction.TransactionDefinition
import org.springframework.transaction.support.TransactionTemplate
import tools.jackson.databind.json.JsonMapper
import java.time.Clock
import java.time.Instant
import java.time.LocalDate

/** 인사 시스템이 보낸 직원 한 명. 값이 빈 선택 항목은 "보내지 않음"으로 보고 기존 값을 둔다 */
data class HrEmployeeRecord(
    val empNo: String?,
    val name: String?,
    val email: String? = null,
    val phone: String? = null,
    val hireDate: LocalDate? = null,
    val orgCode: String?,
    val jobTitle: String? = null,
    val jobGrade: String? = null,
    val isManager: Boolean? = null,
    /** EMPLOYED, LEAVE, RETIRED. 레코드마다 오류를 알리려고 문자열로 받는다 */
    val employmentStatus: String?,
    val retireDate: LocalDate? = null,
)

/** 레코드 처리 결과. 한 레코드에 여러 개가 붙을 수 있다 (예: UPDATED + TRANSFERRED) */
enum class HrSyncAction {
    CREATED, UPDATED, TRANSFERRED, MEMBERSHIP_UPDATED, ON_LEAVE, RETURNED,
    RETIRED, RETIRE_SCHEDULED, RETIRE_CANCELLED, SKIPPED, UNCHANGED, ERROR,
}

data class HrRecordResult(val empNo: String?, val subjectId: Long?, val actions: List<HrSyncAction>, val message: String? = null)

/** 피드에 없는 사용 중(ACTIVE·DISABLED) 사용자. 보고만 하고 퇴사 처리하지 않는다 */
data class HrMissingUser(val subjectId: Long, val empNo: String, val name: String, val status: SubjectStatus)

data class HrSyncResult(
    val runId: Long,
    val dryRun: Boolean,
    val counts: Map<HrSyncAction, Int>,
    val records: List<HrRecordResult>,
    /** reportMissing 을 요청하지 않았으면 null */
    val missing: List<HrMissingUser>?,
)

data class HrRecordError(val empNo: String?, val message: String)

data class HrSyncRunView(
    val runId: Long,
    val dryRun: Boolean,
    val startedAt: Instant,
    val finishedAt: Instant,
    val actorSubjectId: Long?,
    val total: Int,
    val counts: Map<String, Int>,
    val errors: List<HrRecordError>,
    val missingCount: Int?,
)

/**
 * 인사 시스템을 원본으로 입사·이동·휴직·퇴사를 맞춘다. 키는 사번(empNo)이다.
 *
 * - 레코드마다 별도 트랜잭션으로 처리해, 한 레코드가 실패해도 나머지는 반영된다. 미리보기(dryRun)는 레코드마다 계산한 뒤 롤백한다.
 * - 변경은 기존 서비스(UserService·MembershipService)를 거치므로 조직 역할 동기화·전적 처리·세션 회수·감사 기록이 평소처럼 일어난다.
 * - 로그인 계정은 만들지 않는다. 계정은 따로 발급하거나 이후 SSO 로 연결한다.
 * - 외부 사용자(EXTERNAL)는 사번이 없어 맞춰지지 않고, 피드에 없는 사용자 보고에서도 빠진다.
 * - 재직 상태의 원본은 인사 시스템이다. 인사 연동 대상 사용자를 콘솔에서 "사용 중지"해도 다음 연동에서 재직(EMPLOYED)이면 다시 사용으로 바뀐다.
 */
@Service
class HrSyncService(
    private val userRepository: UserRepository,
    private val organizationRepository: OrganizationRepository,
    private val membershipRepository: SubjectOrganizationRepository,
    private val userService: UserService,
    private val membershipService: MembershipService,
    private val runRepository: HrSyncRunRepository,
    private val jsonMapper: JsonMapper,
    private val clock: Clock,
    transactionManager: PlatformTransactionManager,
) {
    private val log = LoggerFactory.getLogger(javaClass)

    /** 호출하는 쪽 트랜잭션과 섞이지 않도록 늘 새 트랜잭션 */
    private val newTransaction = TransactionTemplate(transactionManager).apply {
        propagationBehavior = TransactionDefinition.PROPAGATION_REQUIRES_NEW
    }

    /**
     * @param excludedEmpNos 피드에 없어도 보고하지 않을 사번 (초기 관리자 등 인사 시스템 밖의 계정)
     */
    fun sync(
        employees: List<HrEmployeeRecord>,
        dryRun: Boolean,
        reportMissing: Boolean,
        excludedEmpNos: Set<String>,
        actorSubjectId: Long?,
    ): HrSyncResult {
        val startedAt = clock.instant()
        val seen = HashSet<String>()
        val records = employees.map { record ->
            val error = validate(record) ?: duplicate(record, seen)
            if (error != null) HrRecordResult(record.empNo, null, listOf(HrSyncAction.ERROR), error) else process(record, dryRun)
        }
        val missing = if (reportMissing) missing(employees, excludedEmpNos) else null
        val counts = HrSyncAction.entries.associateWith { action -> records.count { action in it.actions } }.filterValues { it > 0 }
        val errors = records.filter { HrSyncAction.ERROR in it.actions }.take(MAX_STORED_ERRORS)
            .map { HrRecordError(it.empNo, it.message.orEmpty()) }
        val run = newTransaction.execute {
            runRepository.save(
                HrSyncRun(
                    dryRun = dryRun,
                    startedAt = startedAt,
                    finishedAt = clock.instant(),
                    actorSubjectId = actorSubjectId,
                    total = records.size,
                    summary = jsonMapper.writeValueAsString(counts),
                    errors = jsonMapper.writeValueAsString(errors),
                    missingCount = missing?.size,
                ),
            )
        } ?: throw IllegalStateException("HR 연동 실행 기록을 저장하지 못했습니다")
        return HrSyncResult(run.requireId(), dryRun, counts, records, missing)
    }

    fun recentRuns(): List<HrSyncRunView> = runRepository.findTop50ByOrderByIdDesc().map { run ->
        HrSyncRunView(
            runId = run.requireId(),
            dryRun = run.dryRun,
            startedAt = run.startedAt,
            finishedAt = run.finishedAt,
            actorSubjectId = run.actorSubjectId,
            total = run.total,
            counts = jsonMapper.readTree(run.summary).properties().associate { it.key to it.value.asInt() },
            errors = jsonMapper.readTree(run.errors).toList().map { HrRecordError(it.get("empNo")?.takeUnless { n -> n.isNull }?.asString(), it.path("message").asString()) },
            missingCount = run.missingCount,
        )
    }

    private fun process(record: HrEmployeeRecord, dryRun: Boolean): HrRecordResult = try {
        newTransaction.execute { tx ->
            val result = apply(record)
            if (dryRun) {
                // 제약 위반도 미리보기에서 드러나도록 DB 에 내보낸 뒤 롤백한다
                userRepository.flush()
                tx.setRollbackOnly()
            }
            result
        } ?: throw IllegalStateException("레코드 처리 결과가 없습니다")
    } catch (e: IamException) {
        HrRecordResult(record.empNo, null, listOf(HrSyncAction.ERROR), e.message)
    } catch (e: DataIntegrityViolationException) {
        log.info("HR 연동 레코드 무결성 위반: empNo={}, {}", record.empNo, e.mostSpecificCause.message)
        HrRecordResult(record.empNo, null, listOf(HrSyncAction.ERROR), "이미 있는 값이거나 존재하지 않는 대상을 참조합니다")
    } catch (e: RuntimeException) {
        // 한 레코드의 예상하지 못한 오류로 나머지가 멈추지 않게 한다. 내용은 로그에만 남긴다
        log.error("HR 연동 레코드 처리 실패: empNo={}", record.empNo, e)
        HrRecordResult(record.empNo, null, listOf(HrSyncAction.ERROR), "처리하지 못했습니다")
    }

    /** 검증을 마친 레코드 하나를 반영한다 (트랜잭션 안) */
    private fun apply(record: HrEmployeeRecord): HrRecordResult {
        val empNo = record.empNo.orEmpty().trim()
        val status = EmploymentStatus.valueOf(record.employmentStatus.orEmpty().trim())
        val today = LocalDate.now(clock)
        // 퇴사(RETIRED)인데 날짜가 없으면 오늘. 재직·휴직이어도 퇴사일이 오면 그날 퇴사한다
        val retireOn = if (status == EmploymentStatus.RETIRED) record.retireDate ?: today else record.retireDate
        val retireNow = retireOn != null && !retireOn.isAfter(today)
        val user = userRepository.findByEmpNo(empNo)
        val actions = mutableListOf<HrSyncAction>()

        if (user == null) {
            if (retireNow) return HrRecordResult(empNo, null, listOf(HrSyncAction.SKIPPED), "등록되지 않은 퇴사자는 만들지 않습니다")
            val org = activeOrg(record.orgCode.orgCode())
            val created = userService.create(empNo, record.name.orEmpty().trim(), record.email.clean(), record.phone.clean(), record.hireDate)
            val subjectId = created.requireId()
            membershipService.join(subjectId, org.requireId(), MembershipType.PRIMARY, record.jobTitle.clean(), record.jobGrade.clean(), record.isManager ?: false)
            actions += HrSyncAction.CREATED
            if (status == EmploymentStatus.LEAVE) {
                userService.startLeave(subjectId)
                actions += HrSyncAction.ON_LEAVE
            }
            if (retireOn != null) {
                userService.retire(subjectId, retireOn)
                actions += HrSyncAction.RETIRE_SCHEDULED
            }
            return HrRecordResult(empNo, subjectId, actions)
        }

        val subjectId = user.requireId()
        if (user.status == SubjectStatus.RETIRED) return HrRecordResult(empNo, subjectId, listOf(HrSyncAction.UNCHANGED), "이미 퇴사 처리된 사용자입니다")
        if (retireNow) {
            userService.retire(subjectId, retireOn)
            return HrRecordResult(empNo, subjectId, listOf(HrSyncAction.RETIRED))
        }
        if (updateProfile(user, record)) actions += HrSyncAction.UPDATED
        updateMembership(subjectId, record)?.let { actions += it }
        updateEmployment(user, status)?.let { actions += it }
        updateRetireSchedule(user, retireOn)?.let { actions += it }
        return HrRecordResult(empNo, subjectId, actions.ifEmpty { listOf(HrSyncAction.UNCHANGED) })
    }

    private fun updateProfile(user: User, record: HrEmployeeRecord): Boolean {
        val name = record.name.orEmpty().trim()
        val email = record.email.clean() ?: user.email
        val phone = record.phone.clean() ?: user.phone
        val hireDate = record.hireDate ?: user.hireDate
        if (name == user.name && email == user.email && phone == user.phone && hireDate == user.hireDate) return false
        userService.update(user.requireId(), name, email, phone, hireDate)
        return true
    }

    /** 주 소속 조직이 다르면 이동(전적·전보), 같으면 직위·직급·조직장 여부만 맞춘다 */
    private fun updateMembership(subjectId: Long, record: HrEmployeeRecord): HrSyncAction? {
        val primary = membershipRepository.findActivePrimary(subjectId)
        val orgCode = record.orgCode.orgCode()
        val org = organizationRepository.findByOrgCode(orgCode) ?: throw BusinessRuleException("없는 조직 코드입니다: $orgCode")
        if (primary == null || primary.orgId != org.requireId()) {
            if (!org.isActive) throw BusinessRuleException("사용하지 않는 조직입니다: $orgCode")
            // 조직장 여부는 조직에 따른 것이라 옮길 때 이어받지 않는다
            membershipService.transferPrimary(
                subjectId, org.requireId(),
                record.jobTitle.clean() ?: primary?.jobTitle, record.jobGrade.clean() ?: primary?.jobGrade, record.isManager ?: false,
            )
            return HrSyncAction.TRANSFERRED
        }
        val jobTitle = record.jobTitle.clean() ?: primary.jobTitle
        val jobGrade = record.jobGrade.clean() ?: primary.jobGrade
        val isManager = record.isManager ?: primary.isManager
        if (jobTitle == primary.jobTitle && jobGrade == primary.jobGrade && isManager == primary.isManager) return null
        membershipService.updateJob(primary.requireId(), jobTitle, jobGrade, isManager)
        return HrSyncAction.MEMBERSHIP_UPDATED
    }

    /** 휴직이면 사용 안 함, 재직이면 사용 안 함을 다시 사용으로. 잠김은 건드리지 않는다 */
    private fun updateEmployment(user: User, status: EmploymentStatus): HrSyncAction? = when (status) {
        EmploymentStatus.LEAVE ->
            if (user.employmentStatus != EmploymentStatus.LEAVE || user.status == SubjectStatus.ACTIVE) {
                userService.startLeave(user.requireId())
                HrSyncAction.ON_LEAVE
            } else {
                null
            }
        EmploymentStatus.EMPLOYED ->
            if (user.employmentStatus != EmploymentStatus.EMPLOYED || user.status == SubjectStatus.DISABLED) {
                userService.returnToWork(user.requireId())
                HrSyncAction.RETURNED
            } else {
                null
            }
        EmploymentStatus.RETIRED -> null // 미래 퇴사일: 그날까지 지금 상태를 둔다
    }

    /** 미래 퇴사일이면 예약하고, 퇴사일이 빠졌으면 예약을 취소한다 (인사 시스템에서 퇴사가 철회된 경우) */
    private fun updateRetireSchedule(user: User, retireOn: LocalDate?): HrSyncAction? = when {
        retireOn != null && retireOn != user.retireDate -> {
            userService.retire(user.requireId(), retireOn)
            HrSyncAction.RETIRE_SCHEDULED
        }
        retireOn == null && user.retireDate != null -> {
            userService.cancelScheduledRetire(user.requireId())
            HrSyncAction.RETIRE_CANCELLED
        }
        else -> null
    }

    private fun activeOrg(orgCode: String): Organization {
        val org = organizationRepository.findByOrgCode(orgCode) ?: throw BusinessRuleException("없는 조직 코드입니다: $orgCode")
        if (!org.isActive) throw BusinessRuleException("사용하지 않는 조직입니다: $orgCode")
        return org
    }

    private fun missing(employees: List<HrEmployeeRecord>, excludedEmpNos: Set<String>): List<HrMissingUser> {
        val inFeed = employees.mapNotNull { it.empNo?.trim()?.ifEmpty { null } }.toSet()
        return newTransaction.execute {
            // 외부 사용자(EXTERNAL)는 인사 시스템 대상이 아니므로 보고하지 않는다
            userRepository.findByStatusIn(listOf(SubjectStatus.ACTIVE, SubjectStatus.DISABLED))
                .filter { it.userKind == UserKind.EMPLOYEE }
                .mapNotNull { u -> u.empNo?.let { HrMissingUser(u.requireId(), it, u.name, u.status) } }
                .filter { it.empNo !in inFeed && it.empNo !in excludedEmpNos }
                .sortedBy { it.empNo }
        }.orEmpty()
    }

    /** 레코드 형식 검사. 문제가 없으면 null */
    private fun validate(r: HrEmployeeRecord): String? = when {
        r.empNo.isNullOrBlank() -> "사번(empNo)이 필요합니다"
        r.empNo.trim().length > 50 -> "사번은 50자까지입니다"
        r.name.isNullOrBlank() -> "이름(name)이 필요합니다"
        r.name.trim().length > 200 -> "이름은 200자까지입니다"
        r.orgCode.isNullOrBlank() -> "조직 코드(orgCode)가 필요합니다"
        r.employmentStatus.isNullOrBlank() -> "재직 상태(employmentStatus)가 필요합니다"
        EmploymentStatus.entries.none { it.name == r.employmentStatus.trim() } -> "재직 상태는 EMPLOYED, LEAVE, RETIRED 중 하나입니다: ${r.employmentStatus}"
        r.email.clean()?.let { it.length > 255 || !EMAIL.matches(it) } == true -> "이메일 형식이 올바르지 않습니다"
        (r.phone.clean()?.length ?: 0) > 30 -> "전화번호는 30자까지입니다"
        (r.jobTitle.clean()?.length ?: 0) > 100 -> "직위는 100자까지입니다"
        (r.jobGrade.clean()?.length ?: 0) > 100 -> "직급은 100자까지입니다"
        else -> null
    }

    private fun duplicate(r: HrEmployeeRecord, seen: MutableSet<String>): String? =
        if (seen.add(r.empNo.orEmpty().trim())) null else "같은 사번이 피드에 두 번 있습니다"

    private fun String?.clean(): String? = this?.trim()?.ifEmpty { null }

    private fun String?.orgCode(): String = orEmpty().trim()

    companion object {
        const val MAX_STORED_ERRORS = 100
        private val EMAIL = Regex("^[^@\\s]+@[^@\\s]+$")
    }
}
