package com.didrakon.iam.identity.organization

import com.didrakon.iam.common.event.AdminChangeEvent
import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.common.error.NotFoundException
import com.didrakon.iam.identity.event.OrganizationMovedEvent
import org.springframework.context.ApplicationEventPublisher
import org.springframework.data.repository.findByIdOrNull
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
@Transactional
class OrganizationService(
    private val organizationRepository: OrganizationRepository,
    private val membershipRepository: SubjectOrganizationRepository,
    private val eventPublisher: ApplicationEventPublisher,
) {
    fun create(orgCode: String, orgName: String, orgType: OrgType, parentOrgId: Long?): Organization {
        val parent = parentOrgId?.let { find(it) }
        val organization = organizationRepository.save(Organization(orgCode, orgName, orgType))
        // 법인은 저장 후 생긴 자기 ID 를 소속 법인으로 가지므로 저장한 뒤에 배치한다
        organization.placeUnder(parent)
        return organization
    }

    /** 하위 조직 전체를 함께 옮기고, 각 조직의 레벨과 소속 법인을 다시 계산한다 */
    fun move(orgId: Long, newParentOrgId: Long) {
        val organization = find(orgId)
        val newParent = find(newParentOrgId)
        val subtreeIds = organizationRepository.findSubtreeIds(orgId)
        if (newParentOrgId in subtreeIds) {
            throw BusinessRuleException("조직을 자기 자신이나 하위 조직 아래로 옮길 수 없습니다: $orgId → $newParentOrgId")
        }
        // 이동 전 부모 기준으로 묶어 둔다. 하위 조직의 부모 ID 는 아래 순회에서 자기 차례 전까지 바뀌지 않는다
        val childrenByParentId = organizationRepository.findAllById(subtreeIds).groupBy { it.parentOrgId }

        organization.placeUnder(newParent)
        val queue = ArrayDeque(listOf(organization))
        while (queue.isNotEmpty()) {
            val parent = queue.removeFirst()
            childrenByParentId[parent.id].orEmpty().forEach { child ->
                child.placeUnder(parent)
                queue.addLast(child)
            }
        }
        // 구독자가 재귀 SQL 로 바뀐 트리를 읽으므로 먼저 반영한다
        organizationRepository.flush()
        eventPublisher.publishEvent(OrganizationMovedEvent(orgId, subtreeIds))
    }

    fun update(orgId: Long, orgName: String, orgType: OrgType): Organization {
        val organization = find(orgId)
        if (orgName.isBlank()) throw BusinessRuleException("조직 이름이 필요합니다")
        val before = snapshot(organization)
        organization.update(orgName.trim(), orgType)
        eventPublisher.publishEvent(AdminChangeEvent("ORGANIZATION", orgId, "UPDATE", before, snapshot(organization)))
        return organization
    }

    /** 쓰지 않게 된 조직을 닫는다. 구성원이나 사용 중인 하위 조직이 남아 있으면 먼저 옮겨야 한다 */
    fun changeActive(orgId: Long, active: Boolean): Organization {
        val organization = find(orgId)
        if (organization.isActive == active) return organization
        if (!active) {
            if (membershipRepository.findActiveByOrgIdIn(listOf(orgId)).isNotEmpty()) {
                throw BusinessRuleException("구성원이 남아 있는 조직은 닫을 수 없습니다. 구성원을 먼저 옮기세요")
            }
            if (organizationRepository.findAll().any { it.parentOrgId == orgId && it.isActive }) {
                throw BusinessRuleException("사용 중인 하위 조직이 있으면 닫을 수 없습니다")
            }
        }
        val before = snapshot(organization)
        organization.changeActive(active)
        eventPublisher.publishEvent(AdminChangeEvent("ORGANIZATION", orgId, if (active) "ACTIVATE" else "DEACTIVATE", before, snapshot(organization)))
        return organization
    }

    @Transactional(readOnly = true)
    fun get(orgId: Long): Organization = find(orgId)

    /** 트리를 그릴 수 있도록 레벨·코드 순으로 전체를 준다 */
    @Transactional(readOnly = true)
    fun all(): List<Organization> = organizationRepository.findAll().sortedWith(compareBy({ it.orgLevel }, { it.orgCode }))

    private fun snapshot(o: Organization) = mapOf("orgName" to o.orgName, "orgType" to o.orgType.name, "isActive" to o.isActive)

    private fun find(orgId: Long): Organization =
        organizationRepository.findByIdOrNull(orgId) ?: throw NotFoundException("조직", orgId)
}
