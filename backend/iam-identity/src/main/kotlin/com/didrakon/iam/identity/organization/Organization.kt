package com.didrakon.iam.identity.organization

import com.didrakon.iam.common.jpa.BaseTimeEntity
import com.didrakon.iam.common.jpa.IdEntity
import com.didrakon.iam.common.jpa.idEquals
import com.didrakon.iam.common.jpa.idHashCode
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.Table

/**
 * 그룹 → 법인 → 본부·부서·팀·센터로 이어지는 조직 트리.
 * 위치(상위, 레벨, 소속 법인)는 [placeUnder] 로만 바꾼다.
 */
@Entity
@Table(name = "organization")
class Organization(
    orgCode: String,
    orgName: String,
    orgType: OrgType,
) : BaseTimeEntity(), IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "org_id")
    override val id: Long? = null

    @Column(name = "parent_org_id")
    var parentOrgId: Long? = null
        protected set

    /** 가장 가까운 상위 법인(자기 자신 포함). 재귀 없이 법인을 판별하려고 비정규화했다 */
    @Column(name = "company_org_id")
    var companyOrgId: Long? = null
        protected set

    @Column(name = "org_code", nullable = false, length = 100, updatable = false)
    val orgCode: String = orgCode

    @Column(name = "org_name", nullable = false, length = 200)
    var orgName: String = orgName
        protected set

    @Enumerated(EnumType.STRING)
    @Column(name = "org_type", nullable = false, length = 30)
    var orgType: OrgType = orgType
        protected set

    /** 최상위 = 1 */
    @Column(name = "org_level", nullable = false)
    var orgLevel: Int = 1
        protected set

    @Column(name = "is_active", nullable = false)
    var isActive: Boolean = true
        protected set

    /**
     * [parent] 아래(null 이면 최상위)로 옮기고 레벨과 소속 법인을 다시 계산한다.
     * 법인은 자기 자신이 소속 법인이므로 저장되어 ID 가 있어야 한다.
     */
    internal fun placeUnder(parent: Organization?) {
        parentOrgId = parent?.requireId()
        orgLevel = (parent?.orgLevel ?: 0) + 1
        companyOrgId = if (orgType == OrgType.COMPANY) requireId() else parent?.companyOrgId
    }

    internal fun update(orgName: String, orgType: OrgType) {
        this.orgName = orgName
        this.orgType = orgType
    }

    internal fun changeActive(active: Boolean) {
        isActive = active
    }

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

enum class OrgType { GROUP, COMPANY, DIVISION, DEPARTMENT, TEAM, CENTER }
