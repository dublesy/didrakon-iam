package com.didrakon.iam.governance.review

import com.didrakon.iam.authz.assignment.AssignmentSourceType
import com.didrakon.iam.authz.assignment.AssignmentStatus
import com.didrakon.iam.authz.assignment.RoleAssignment
import com.didrakon.iam.authz.assignment.RoleAssignmentRepository
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.role.Role
import com.didrakon.iam.authz.role.RoleRepository
import com.didrakon.iam.authz.scope.ScopeRepository
import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.common.error.NotFoundException
import com.didrakon.iam.governance.breakglass.BreakGlassService
import com.didrakon.iam.governance.delegation.DelegationService
import com.didrakon.iam.governance.event.AccessReviewAction
import com.didrakon.iam.governance.event.AccessReviewCampaignEvent
import com.didrakon.iam.governance.event.AccessReviewDecidedEvent
import com.didrakon.iam.identity.organization.MembershipType
import com.didrakon.iam.identity.organization.OrganizationRepository
import com.didrakon.iam.identity.organization.SubjectOrganizationRepository
import com.didrakon.iam.identity.subject.SubjectRepository
import com.didrakon.iam.identity.subject.UserRepository
import org.slf4j.LoggerFactory
import org.springframework.context.ApplicationEventPublisher
import org.springframework.data.repository.findByIdOrNull
import org.springframework.stereotype.Service
import org.springframework.transaction.PlatformTransactionManager
import org.springframework.transaction.annotation.Propagation
import org.springframework.transaction.annotation.Transactional
import org.springframework.transaction.support.TransactionTemplate
import java.time.Clock
import java.time.Instant

/** 캠페인 생성 조건 */
data class AccessReviewSpec(
    val name: String,
    val scopeType: ReviewScopeType,
    val scopeOrgId: Long? = null,
    val scopeRoleId: Long? = null,
    val includeDescendants: Boolean = true,
    val privilegedOnly: Boolean = false,
    val sources: Set<AssignmentSourceType> = DEFAULT_SOURCES,
    val dueAt: Instant,
    val onOverdue: AccessReviewDecision = AccessReviewDecision.KEEP,
    /** 기한이 지나면 미결정 항목을 상위 조직 관리자에게 넘기고 더 기다리는 날수 (1~30). null 이면 이관 없이 기한에 닫는다 */
    val escalationDays: Int? = null,
)

/** 캠페인과 결정별 항목 수 */
data class AccessReviewProgress(val campaign: AccessReviewCampaign, val counts: Map<AccessReviewDecision, Long>) {
    val total: Long get() = counts.values.sum()
}

/**
 * 관리 콘솔 권한을 가졌거나 곧 받을 사람인지 (iam-app 이 구현한다).
 * 이런 사람의 권한은 조직 관리자(is_manager)가 아니라 재검토 권한을 가진 관리자가 검토한다. is_manager 는 조직 단위 관리자가 바꿀 수 있어,
 * 조직장 검토를 허용하면 조직 단위 관리자가 자기를 검토자로 만들어 다른 관리자의 권한을 회수하거나 유지 확인할 수 있다
 */
fun interface ConsoleAdministrators {
    fun isAdministrator(subjectId: Long): Boolean
}

/** 기본 대상 출처. 비상 접근은 길어야 24시간이라 기본에서 뺀다 */
val DEFAULT_SOURCES = setOf(AssignmentSourceType.DIRECT, AssignmentSourceType.JIT, AssignmentSourceType.DELEGATION)

/**
 * 조직·그룹 규칙으로 생긴 할당은 규칙을 바꿔 검토한다 (개별 회수 경로가 없고, 회수해도 다음 동기화가 다시 만든다).
 * 시스템 할당은 IAM 운영용이라 대상이 아니다
 */
val REVIEWABLE_SOURCES = setOf(AssignmentSourceType.DIRECT, AssignmentSourceType.JIT, AssignmentSourceType.DELEGATION, AssignmentSourceType.BREAK_GLASS)

/**
 * 접근 재검토(Access Review) 캠페인. 개인정보보호법의 접근 권한 정기 점검을 증적과 함께 남긴다.
 *
 * - 만들 때 대상 할당을 항목으로 스냅샷한다. 검토자는 대상자 PRIMARY 소속 조직의 관리자(is_manager) 중 subject ID 가 가장 작은 사람(본인 제외),
 *   없으면 비워 두고 관리자(REVIEW 승인 권한)가 검토한다. 대상자가 관리 콘솔 권한을 가진 사람이면 조직장에게 맡기지 않고 비워 둔다 ([ConsoleAdministrators]).
 * - 결정: 회수(REVOKE)는 출처에 맞는 경로로 바로 회수, 유지(KEEP)는 재검토 표시를 지운다. 본인 권한은 검토할 수 없다.
 * - 이관 날수(escalation_days)가 있으면 기한이 지났을 때 먼저 미결정 항목을 상위 조직 관리자에게 넘긴다: 대상자 주 소속 조직의 상위 조직부터
 *   올라가며 관리자(본인·지금 검토자 제외, subject ID 가 가장 작은 사람)를 찾는다. 못 찾으면 그대로 둔다(관리자가 검토). 그 날수가 더 지나면 닫는다.
 * - 기한이 지나거나 마감하면 남은 항목에 캠페인의 on_overdue 를 적용하고 닫는다. 자동 유지는 사람이 확인한 것이 아니므로 재검토 표시를 지우지 않는다.
 * - 생성·결정·마감마다 이벤트를 내고 audit 이 남긴다. 회수 자체는 역할 변경 이력에도 남는다.
 */
@Service
@Transactional
class AccessReviewService(
    private val campaignRepository: AccessReviewCampaignRepository,
    private val itemRepository: AccessReviewItemRepository,
    private val assignmentRepository: RoleAssignmentRepository,
    private val assignmentService: RoleAssignmentService,
    private val delegationService: DelegationService,
    private val breakGlassService: BreakGlassService,
    private val roleRepository: RoleRepository,
    private val scopeRepository: ScopeRepository,
    private val organizationRepository: OrganizationRepository,
    private val membershipRepository: SubjectOrganizationRepository,
    private val subjectRepository: SubjectRepository,
    private val userRepository: UserRepository,
    private val consoleAdministrators: ConsoleAdministrators,
    private val eventPublisher: ApplicationEventPublisher,
    private val clock: Clock,
    transactionManager: PlatformTransactionManager,
) {
    private val log = LoggerFactory.getLogger(javaClass)
    private val newTransaction = TransactionTemplate(transactionManager).apply {
        propagationBehavior = TransactionTemplate.PROPAGATION_REQUIRES_NEW
    }

    /**
     * 조건에 맞는 지금 유효한 할당을 항목으로 만든다.
     * 재검토 표시(전적 등)가 있는 할당은 범위(조직·역할) 안이면 출처·특권 조건과 관계없이 넣는다 — 이미 담당자 확인이 필요하다고 표시된 할당이기 때문이다.
     */
    fun createCampaign(spec: AccessReviewSpec, createdBy: Long?): AccessReviewCampaign {
        val now = clock.instant()
        validate(spec, now)

        val subjectsInScope: Set<Long>? = spec.scopeOrgId?.takeIf { spec.scopeType == ReviewScopeType.ORGANIZATION }?.let { orgId ->
            val orgIds = if (spec.includeDescendants) organizationRepository.findSubtreeIds(orgId) else listOf(orgId)
            membershipRepository.findActiveByOrgIdIn(orgIds).filter { it.membershipType == MembershipType.PRIMARY }.map { it.subjectId }.toSet()
        }
        val roleFilter = spec.scopeRoleId?.takeIf { spec.scopeType == ReviewScopeType.ROLE }
        val inScope = assignmentRepository.findAllEffective(now, roleFilter).filter { subjectsInScope == null || it.subjectId in subjectsInScope }
        val roles = roleRepository.findAllById(inScope.map { it.roleId }.toSet()).associateBy { it.requireId() }
        val targets = inScope.filter { a ->
            val role = roles[a.roleId] ?: return@filter false
            a.sourceType in REVIEWABLE_SOURCES &&
                (a.reviewRequired || (a.sourceType in spec.sources && (!spec.privilegedOnly || role.isPrivileged)))
        }
        if (targets.isEmpty()) throw BusinessRuleException("조건에 맞는 검토 대상 할당이 없습니다")

        val campaign = campaignRepository.save(
            AccessReviewCampaign(
                spec.name.trim(), spec.scopeType, spec.scopeOrgId, spec.scopeRoleId, spec.includeDescendants, spec.privilegedOnly,
                spec.sources, spec.dueAt, spec.onOverdue, createdBy, now, spec.escalationDays,
            ),
        )
        val snapshots = SnapshotSource(targets)
        itemRepository.saveAll(
            targets.map { a ->
                val reviewerId = snapshots.reviewerOf(a.subjectId)
                AccessReviewItem(
                    campaign.requireId(), a.requireId(), a.subjectId, a.roleId, a.scopeId, a.sourceType, reviewerId,
                    snapshots.snapshot(a, roles.getValue(a.roleId), reviewerId),
                )
            },
        )
        eventPublisher.publishEvent(AccessReviewCampaignEvent(campaign.requireId(), campaign.name, AccessReviewAction.CREATE, targets.size, createdBy))
        return campaign
    }

    /** 관리자 결정. 검토자가 비어 있는 항목도 여기서 정한다 */
    fun decide(itemId: Long, deciderId: Long, decision: AccessReviewDecision, comment: String?): AccessReviewItem {
        val item = itemRepository.findByIdOrNull(itemId) ?: throw NotFoundException("검토 항목", itemId)
        return decideItem(item, deciderId, decision, comment)
    }

    /** 검토자 본인 결정. 배정되지 않은 항목은 있는지도 알려주지 않는다 */
    fun decideAsReviewer(itemId: Long, reviewerId: Long, decision: AccessReviewDecision, comment: String?): AccessReviewItem {
        val item = itemRepository.findByIdOrNull(itemId)?.takeIf { it.reviewerId == reviewerId } ?: throw NotFoundException("검토 항목", itemId)
        // 캠페인을 만든 뒤 관리자가 된 사람도 조직장이 결정하지 못하게 결정할 때 다시 본다
        if (consoleAdministrators.isAdministrator(item.subjectId)) {
            throw BusinessRuleException("관리 콘솔 권한이 있는 사람의 권한은 재검토 관리자가 결정합니다")
        }
        return decideItem(item, reviewerId, decision, comment)
    }

    /** 기한 전에 마감한다. 남은 항목에는 기한 경과와 같은 처리를 한다 */
    fun closeCampaign(campaignId: Long, closedBy: Long?): AccessReviewCampaign {
        val campaign = campaignRepository.findByIdOrNull(campaignId) ?: throw NotFoundException("접근 재검토", campaignId)
        close(campaign, closedBy, "마감 시 미결정")
        return campaign
    }

    /**
     * 기한이 지난 열린 캠페인을 처리한다 (만료 스케줄러): 이관할 차례면 상위 관리자에게 넘기고, 닫을 차례면 닫는다.
     * 캠페인마다 새 트랜잭션이라 한 캠페인이 실패해도 나머지는 처리되고, 실패한 것은 다음 실행에서 다시 시도한다.
     * 스케줄러가 오래 멈췄다가 최종 기한 뒤에 처음 돌면, 이번에 이관하고 다음 실행에서 닫는다.
     */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    fun closeOverdue(): Int {
        val due = campaignRepository.findByStatusAndDueAtLessThanEqual(AccessReviewStatus.OPEN, clock.instant()).map { it.requireId() }
        return due.count { campaignId ->
            try {
                newTransaction.execute {
                    val campaign = campaignRepository.findByIdOrNull(campaignId) ?: return@execute
                    val now = clock.instant()
                    when {
                        campaign.status != AccessReviewStatus.OPEN -> Unit
                        campaign.needsEscalationAt(now) -> escalate(campaign, now)
                        campaign.closableAt(now) -> close(campaign, null, "기한 경과")
                    }
                }
                true
            } catch (e: RuntimeException) {
                log.warn("접근 재검토 {} 기한 처리 실패: {}", campaignId, e.message)
                false
            }
        }
    }

    @Transactional(readOnly = true)
    fun campaigns(): List<AccessReviewProgress> = progress(campaignRepository.findAllByOrderByIdDesc())

    @Transactional(readOnly = true)
    fun campaign(campaignId: Long): AccessReviewProgress {
        val campaign = campaignRepository.findByIdOrNull(campaignId) ?: throw NotFoundException("접근 재검토", campaignId)
        return progress(listOf(campaign)).single()
    }

    @Transactional(readOnly = true)
    fun items(campaignId: Long, decision: AccessReviewDecision? = null): List<AccessReviewItem> =
        if (decision == null) itemRepository.findByCampaignIdOrderById(campaignId)
        else itemRepository.findByCampaignIdAndDecisionOrderById(campaignId, decision)

    /** 내가 검토할 미결정 항목 (열린 캠페인만 미결정 항목을 갖는다) */
    @Transactional(readOnly = true)
    fun pendingFor(reviewerId: Long): List<AccessReviewItem> =
        itemRepository.findByReviewerIdAndDecisionOrderById(reviewerId, AccessReviewDecision.PENDING)

    @Transactional(readOnly = true)
    fun campaignsById(ids: Collection<Long>): Map<Long, AccessReviewCampaign> = campaignRepository.findAllById(ids).associateBy { it.requireId() }

    private fun decideItem(item: AccessReviewItem, deciderId: Long, decision: AccessReviewDecision, comment: String?): AccessReviewItem {
        if (decision == AccessReviewDecision.PENDING) throw BusinessRuleException("유지(KEEP) 또는 회수(REVOKE)로 결정해야 합니다")
        if (item.decision != AccessReviewDecision.PENDING) throw BusinessRuleException("이미 결정된 검토 항목입니다: ${item.id} (${item.decision})")
        if (deciderId == item.subjectId) throw BusinessRuleException("본인의 권한은 검토할 수 없습니다")
        val campaign = campaignRepository.findByIdOrNull(item.campaignId) ?: throw NotFoundException("접근 재검토", item.campaignId)
        campaign.requireOpen()
        apply(campaign, item, decision, deciderId, deciderId, comment?.trim()?.ifEmpty { null })
        return item
    }

    /** 미결정 항목을 상위 조직 관리자에게 넘긴다. 넘길 사람이 없는 항목은 그대로 둔다 */
    private fun escalate(campaign: AccessReviewCampaign, now: Instant) {
        val pending = itemRepository.findByCampaignIdAndDecisionOrderById(campaign.requireId(), AccessReviewDecision.PENDING)
        val escalated = pending.count { item ->
            val next = upperManagerOf(item) ?: return@count false
            item.escalateTo(next, subjectRepository.findByIdOrNull(next)?.subjectName, now)
            true
        }
        campaign.markEscalated(now)
        eventPublisher.publishEvent(AccessReviewCampaignEvent(campaign.requireId(), campaign.name, AccessReviewAction.ESCALATE, escalated, null))
    }

    /** 대상자 주 소속 조직의 상위 조직부터 올라가며 찾은 첫 관리자 (대상자 본인·지금 검토자 제외) */
    private fun upperManagerOf(item: AccessReviewItem): Long? {
        if (consoleAdministrators.isAdministrator(item.subjectId)) return null
        val orgId = membershipRepository.findActivePrimary(item.subjectId)?.orgId ?: return null
        val excluded = setOfNotNull(item.subjectId, item.reviewerId)
        val visited = mutableSetOf(orgId)
        var parentId = organizationRepository.findByIdOrNull(orgId)?.parentOrgId
        while (parentId != null && visited.add(parentId)) {
            val manager = membershipRepository.findActiveByOrgIdIn(listOf(parentId))
                .filter { it.isManager && it.subjectId !in excluded }.minOfOrNull { it.subjectId }
            if (manager != null) return manager
            parentId = organizationRepository.findByIdOrNull(parentId)?.parentOrgId
        }
        return null
    }

    private fun close(campaign: AccessReviewCampaign, actorId: Long?, comment: String) {
        campaign.requireOpen()
        itemRepository.findByCampaignIdAndDecisionOrderById(campaign.requireId(), AccessReviewDecision.PENDING)
            .forEach { apply(campaign, it, campaign.onOverdue, null, actorId, comment) }
        campaign.close(clock.instant())
        val total = itemRepository.findByCampaignIdOrderById(campaign.requireId()).size
        eventPublisher.publishEvent(AccessReviewCampaignEvent(campaign.requireId(), campaign.name, AccessReviewAction.CLOSE, total, actorId))
    }

    /** [decidedBy] 가 null 이면 자동 처리(기한 경과·마감). [actorId] 는 회수·이력에 남는 행위자 */
    private fun apply(
        campaign: AccessReviewCampaign,
        item: AccessReviewItem,
        decision: AccessReviewDecision,
        decidedBy: Long?,
        actorId: Long?,
        comment: String?,
    ) {
        val reason = "접근 재검토 '${campaign.name}'" + (comment?.let { ": $it" } ?: "")
        when (decision) {
            AccessReviewDecision.REVOKE -> revokeAssignment(item, actorId, reason)
            // 자동 유지는 사람이 확인한 것이 아니므로 재검토 표시를 남긴다
            AccessReviewDecision.KEEP -> if (decidedBy != null) assignmentService.completeReview(item.assignmentId, decidedBy, reason)
            AccessReviewDecision.PENDING -> throw IllegalArgumentException("PENDING 은 결정이 아닙니다")
        }
        item.decide(decision, decidedBy, clock.instant(), comment)
        eventPublisher.publishEvent(
            AccessReviewDecidedEvent(
                campaign.requireId(), item.requireId(), item.assignmentId, item.subjectId, item.roleId, decision, decidedBy, actorId, comment,
            ),
        )
    }

    /** 출처에 맞는 경로로 회수한다. 이미 끝난(회수·만료·기간 경과) 할당은 회수할 것이 없으므로 결정만 남긴다 */
    private fun revokeAssignment(item: AccessReviewItem, revokedBy: Long?, reason: String) {
        val assignment = assignmentRepository.findByIdOrNull(item.assignmentId) ?: throw NotFoundException("역할 할당", item.assignmentId)
        if (assignment.status != AssignmentStatus.ACTIVE || !assignment.isEffectiveAt(clock.instant())) return
        when (assignment.sourceType) {
            AssignmentSourceType.DIRECT -> assignmentService.revoke(assignment.requireId(), revokedBy, reason)
            AssignmentSourceType.JIT -> assignmentService.revokeForSource(AssignmentSourceType.JIT, sourceIdOf(assignment), revokedBy, reason)
            AssignmentSourceType.DELEGATION -> delegationService.revoke(sourceIdOf(assignment), revokedBy, reason)
            AssignmentSourceType.BREAK_GLASS -> breakGlassService.end(sourceIdOf(assignment), revokedBy)
            AssignmentSourceType.GROUP, AssignmentSourceType.ORGANIZATION, AssignmentSourceType.SYSTEM ->
                throw BusinessRuleException("${assignment.sourceType} 할당은 개별로 회수할 수 없습니다. 조직·그룹 역할 규칙이나 소속을 바꿔 회수하세요")
        }
    }

    private fun sourceIdOf(assignment: RoleAssignment): Long =
        assignment.sourceId ?: throw IllegalStateException("${assignment.sourceType} 할당에 출처 ID 가 없습니다: ${assignment.id}")

    private fun validate(spec: AccessReviewSpec, now: Instant) {
        if (spec.name.isBlank()) throw BusinessRuleException("캠페인 이름이 필요합니다")
        if (!spec.dueAt.isAfter(now)) throw BusinessRuleException("검토 기한은 지금 이후여야 합니다")
        if (spec.onOverdue == AccessReviewDecision.PENDING) throw BusinessRuleException("기한 경과 처리는 유지(KEEP) 또는 회수(REVOKE)입니다")
        if (spec.escalationDays != null && spec.escalationDays !in 1..30) throw BusinessRuleException("상위 관리자 이관 날수는 1~30일입니다")
        if (spec.sources.isEmpty()) throw BusinessRuleException("대상 할당 출처를 하나 이상 고르세요")
        val unsupported = spec.sources - REVIEWABLE_SOURCES
        if (unsupported.isNotEmpty()) {
            throw BusinessRuleException("$unsupported 할당은 재검토 대상이 아닙니다. 조직·그룹 할당은 역할 규칙을 바꿔 검토합니다")
        }
        when (spec.scopeType) {
            ReviewScopeType.ALL -> if (spec.scopeOrgId != null || spec.scopeRoleId != null) throw BusinessRuleException("전체 대상에는 조직·역할을 지정하지 않습니다")
            ReviewScopeType.ORGANIZATION -> {
                val orgId = spec.scopeOrgId ?: throw BusinessRuleException("대상 조직을 지정하세요")
                if (spec.scopeRoleId != null) throw BusinessRuleException("조직 대상에는 역할을 지정하지 않습니다")
                if (!organizationRepository.existsById(orgId)) throw NotFoundException("조직", orgId)
            }
            ReviewScopeType.ROLE -> {
                val roleId = spec.scopeRoleId ?: throw BusinessRuleException("대상 역할을 지정하세요")
                if (spec.scopeOrgId != null) throw BusinessRuleException("역할 대상에는 조직을 지정하지 않습니다")
                if (!roleRepository.existsById(roleId)) throw NotFoundException("역할", roleId)
            }
        }
    }

    private fun progress(campaigns: List<AccessReviewCampaign>): List<AccessReviewProgress> {
        if (campaigns.isEmpty()) return emptyList()
        val counts = itemRepository.countByDecision(campaigns.map { it.requireId() }).groupBy { it.campaignId }
        return campaigns.map { c ->
            AccessReviewProgress(c, counts[c.requireId()].orEmpty().associate { it.decision to it.count })
        }
    }

    /** 스냅샷에 필요한 이름·소속·검토자를 대상 subject 단위로 한 번씩 읽는다 */
    private inner class SnapshotSource(targets: List<RoleAssignment>) {
        private val subjectIds = targets.map { it.subjectId }.toSet()
        private val primaryOrg = subjectIds.associateWith { membershipRepository.findActivePrimary(it)?.orgId }
        private val orgIds = primaryOrg.values.filterNotNull().toSet()
        private val managersByOrg = membershipRepository.findActiveByOrgIdIn(orgIds.ifEmpty { setOf(-1L) })
            .filter { it.isManager }.groupBy({ it.orgId }, { it.subjectId })
        private val reviewers = subjectIds.associateWith { subjectId ->
            if (consoleAdministrators.isAdministrator(subjectId)) return@associateWith null
            primaryOrg[subjectId]?.let { orgId -> managersByOrg[orgId].orEmpty().filter { it != subjectId }.minOrNull() }
        }
        private val names = subjectRepository.findAllById(subjectIds + reviewers.values.filterNotNull()).associate { it.requireId() to it.subjectName }
        private val empNos = userRepository.findAllById(subjectIds).associate { it.requireId() to it.empNo }
        private val orgNames = organizationRepository.findAllById(orgIds).associate { it.requireId() to it.orgName }
        private val scopeNames = scopeRepository.findAllById(targets.map { it.scopeId }.toSet()).associate { it.requireId() to it.scopeName }

        fun reviewerOf(subjectId: Long): Long? = reviewers[subjectId]

        fun snapshot(a: RoleAssignment, role: Role, reviewerId: Long?) = ReviewSnapshot(
            subjectName = names[a.subjectId] ?: a.subjectId.toString(),
            empNo = empNos[a.subjectId],
            orgName = primaryOrg[a.subjectId]?.let { orgNames[it] },
            roleCode = role.roleCode,
            roleName = role.roleName,
            isPrivileged = role.isPrivileged,
            scopeName = scopeNames[a.scopeId] ?: a.scopeId.toString(),
            reviewerName = reviewerId?.let { names[it] },
            validFrom = a.validFrom,
            validUntil = a.validUntil,
            reviewRequired = a.reviewRequired,
        )
    }
}
