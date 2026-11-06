package com.didrakon.iam.governance

import com.didrakon.iam.authz.AuthzFixture
import com.didrakon.iam.authz.IntegrationTest
import com.didrakon.iam.authz.assignment.AssignmentStatus
import com.didrakon.iam.authz.assignment.RoleAssignmentRepository
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.governance.review.AccessReviewCampaign
import com.didrakon.iam.governance.review.AccessReviewDecision
import com.didrakon.iam.governance.review.AccessReviewService
import com.didrakon.iam.governance.review.AccessReviewSpec
import com.didrakon.iam.governance.review.AccessReviewStatus
import com.didrakon.iam.governance.review.ReviewScopeType
import com.didrakon.iam.identity.organization.MembershipService
import com.didrakon.iam.identity.organization.MembershipType
import com.didrakon.iam.identity.organization.OrgType
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.jdbc.core.JdbcTemplate
import java.time.Duration
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * 기한이 지난 캠페인 처리. 스케줄러는 캠페인마다 새 트랜잭션을 쓰므로 데이터가 커밋되어 있어야 한다 (롤백하지 않는 테스트, 고유 데이터 사용).
 * 테스트 프로필은 스케줄링을 끄므로 스케줄러가 부르는 메서드를 직접 부른다.
 */
@IntegrationTest
class AccessReviewOverdueTests @Autowired constructor(
    private val reviewService: AccessReviewService,
    private val assignmentService: RoleAssignmentService,
    private val assignmentRepository: RoleAssignmentRepository,
    private val membershipService: MembershipService,
    private val fixture: AuthzFixture,
    private val jdbc: JdbcTemplate,
) {
    @Test
    fun `기한이 지나면 미결정 항목에 기한 경과 처리를 적용하고 캠페인을 닫는다`() {
        val team = fixture.org(OrgType.TEAM)
        val manager = fixture.user().also { membershipService.join(it, team, MembershipType.PRIMARY, isManager = true) }
        val user = fixture.user().also { fixture.join(it, team) }
        val decided = assignmentService.assignDirect(user, fixture.role().requireId()).requireId()
        val pending = assignmentService.assignDirect(user, fixture.role().requireId()).requireId()
        val revoking = campaign(team, AccessReviewDecision.REVOKE)
        val keeping = campaign(team, AccessReviewDecision.KEEP)
        val decidedItem = reviewService.items(revoking).single { it.assignmentId == decided }
        reviewService.decideAsReviewer(decidedItem.requireId(), manager, AccessReviewDecision.KEEP, "필요")

        assertEquals(0, reviewService.closeOverdue(), "기한 전에는 닫지 않는다")
        // 시간대 변환을 피하려고 충분히 지난 고정 시각을 넣는다
        jdbc.update("UPDATE access_review_campaign SET due_at = '2000-01-01 00:00:00' WHERE campaign_id IN (?, ?)", revoking, keeping)

        assertTrue(reviewService.closeOverdue() >= 2)

        assertEquals(AccessReviewStatus.CLOSED, reviewService.campaign(revoking).campaign.status)
        assertEquals(AccessReviewStatus.CLOSED, reviewService.campaign(keeping).campaign.status)
        val revoked = reviewService.items(revoking).single { it.assignmentId == pending }
        assertEquals(AccessReviewDecision.REVOKE, revoked.decision)
        assertNull(revoked.decidedBy)
        assertEquals("기한 경과", revoked.comment)
        assertEquals(AccessReviewDecision.KEEP, reviewService.items(revoking).single { it.assignmentId == decided }.decision, "이미 정한 항목은 그대로")
        assertEquals(AssignmentStatus.REVOKED, assignmentRepository.findById(pending).orElseThrow().status)
        assertEquals(AssignmentStatus.ACTIVE, assignmentRepository.findById(decided).orElseThrow().status)
        assertTrue(reviewService.items(keeping).all { it.decision == AccessReviewDecision.KEEP && it.decidedBy == null && it.comment == "기한 경과" })
        val closeAudit = jdbc.queryForList(
            "SELECT action FROM audit_event WHERE resource_type = 'ACCESS_REVIEW_CAMPAIGN' AND resource_id = ? ORDER BY event_id",
            String::class.java, revoking.toString(),
        )
        assertEquals(listOf("REVIEW_CAMPAIGN_CREATE", "REVIEW_CAMPAIGN_CLOSE"), closeAudit)
        assertEquals(0, reviewService.closeOverdue(), "닫힌 캠페인은 다시 처리하지 않는다")
    }

    @Test
    fun `이관 날수가 있으면 기한이 지났을 때 상위 조직 관리자에게 넘기고 다음 처리에서 닫는다`() {
        val division = fixture.org(OrgType.DEPARTMENT)
        val director = fixture.user("본부장").also { membershipService.join(it, division, MembershipType.PRIMARY, isManager = true) }
        val middle = fixture.org(OrgType.DEPARTMENT, division) // 관리자 없음: 한 단계 더 올라간다
        val team = fixture.org(OrgType.TEAM, middle)
        val lead = fixture.user("팀장").also { membershipService.join(it, team, MembershipType.PRIMARY, isManager = true) }
        val member = fixture.user().also { fixture.join(it, team) }
        val decided = assignmentService.assignDirect(member, fixture.role().requireId()).requireId()
        val pending = assignmentService.assignDirect(member, fixture.role().requireId()).requireId()
        val leadPending = assignmentService.assignDirect(lead, fixture.role().requireId()).requireId()
        val campaignId = reviewService.createCampaign(
            AccessReviewSpec(
                "이관 테스트", ReviewScopeType.ORGANIZATION, scopeOrgId = team, dueAt = Instant.now().plus(Duration.ofDays(1)),
                onOverdue = AccessReviewDecision.REVOKE, escalationDays = 3,
            ),
            null,
        ).requireId()
        val decidedItem = reviewService.items(campaignId).single { it.assignmentId == decided }
        reviewService.decideAsReviewer(decidedItem.requireId(), lead, AccessReviewDecision.KEEP, "필요")
        assertNull(reviewService.items(campaignId).single { it.assignmentId == leadPending }.reviewerId, "팀장 본인 항목은 검토자가 없다")
        jdbc.update("UPDATE access_review_campaign SET due_at = '2000-01-01 00:00:00' WHERE campaign_id = ?", campaignId)

        reviewService.closeOverdue()

        val campaign = reviewService.campaign(campaignId).campaign
        assertEquals(AccessReviewStatus.OPEN, campaign.status, "이관한 실행에서는 닫지 않는다")
        assertTrue(campaign.escalatedAt != null)
        val escalated = reviewService.items(campaignId).single { it.assignmentId == pending }
        assertEquals(director, escalated.reviewerId, "관리자 없는 중간 조직을 건너뛰고 본부장에게 간다")
        assertEquals("본부장", escalated.reviewerName)
        assertEquals(lead, escalated.escalatedFromId)
        assertEquals("팀장", escalated.escalatedFromName)
        val leadItem = reviewService.items(campaignId).single { it.assignmentId == leadPending }
        assertEquals(director, leadItem.reviewerId, "검토자가 없던 항목도 상위 관리자에게 간다")
        assertNull(leadItem.escalatedFromId)
        assertEquals(lead, reviewService.items(campaignId).single { it.assignmentId == decided }.reviewerId, "이미 정한 항목은 그대로")
        assertEquals(setOf(pending, leadPending), reviewService.pendingFor(director).filter { it.campaignId == campaignId }.map { it.assignmentId }.toSet())
        assertTrue(reviewService.pendingFor(lead).none { it.campaignId == campaignId }, "원래 검토자 할 일에서는 빠진다")

        // 넘겨받은 관리자가 하나를 정하고, 최종 기한(여기서는 이미 지남)이 지나 다음 처리에서 나머지에 기한 경과 처리를 하고 닫는다
        reviewService.decideAsReviewer(leadItem.requireId(), director, AccessReviewDecision.KEEP, "확인")
        reviewService.closeOverdue()
        assertEquals(AccessReviewStatus.CLOSED, reviewService.campaign(campaignId).campaign.status)
        assertEquals(AccessReviewDecision.REVOKE, reviewService.items(campaignId).single { it.assignmentId == pending }.decision)
        assertEquals(AssignmentStatus.REVOKED, assignmentRepository.findById(pending).orElseThrow().status)
        val audit = jdbc.queryForList(
            "SELECT action FROM audit_event WHERE resource_type = 'ACCESS_REVIEW_CAMPAIGN' AND resource_id = ? ORDER BY event_id",
            String::class.java, campaignId.toString(),
        )
        assertEquals(listOf("REVIEW_CAMPAIGN_CREATE", "REVIEW_CAMPAIGN_ESCALATE", "REVIEW_CAMPAIGN_CLOSE"), audit)
    }

    @Test
    fun `이관 캠페인은 기한 뒤 이관하고 최종 기한까지 기다린다`() {
        val due = Instant.parse("2026-11-01T00:00:00Z")
        val c = AccessReviewCampaign(
            "x", ReviewScopeType.ALL, null, null, true, false, emptySet(), due, AccessReviewDecision.KEEP, null, due.minusSeconds(60), escalationDays = 2,
        )
        assertFalse(c.needsEscalationAt(due.minusSeconds(1)))
        assertTrue(c.needsEscalationAt(due))
        assertFalse(c.closableAt(due.plus(Duration.ofDays(3))), "이관 전에는 닫지 않는다")
        assertEquals(due, c.currentDueAt)
        val plain = AccessReviewCampaign("y", ReviewScopeType.ALL, null, null, true, false, emptySet(), due, AccessReviewDecision.KEEP, null, due)
        assertFalse(plain.needsEscalationAt(due))
        assertTrue(plain.closableAt(due))
        assertEquals(due.plus(Duration.ofDays(2)), c.finalDueAt)
    }

    private fun campaign(orgId: Long, onOverdue: AccessReviewDecision): Long = reviewService.createCampaign(
        AccessReviewSpec("기한 테스트", ReviewScopeType.ORGANIZATION, scopeOrgId = orgId, dueAt = Instant.now().plus(Duration.ofDays(1)), onOverdue = onOverdue),
        null,
    ).requireId()
}
