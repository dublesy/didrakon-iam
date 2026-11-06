package com.didrakon.iam.api.support

import com.didrakon.iam.authz.assignment.AssignmentSourceType
import com.didrakon.iam.authz.assignment.GrantRequest
import com.didrakon.iam.authz.assignment.RoleGrantGuard
import com.didrakon.iam.common.error.BusinessRuleException
import org.springframework.stereotype.Component

/**
 * 관리 콘솔 권한이 있는 역할은 조직·그룹 역할 규칙으로 부여하지 않는다 ([AdminAuthorizer.requireNotConsoleRole] 과 같은 이유).
 * 규칙을 만들 때만 막으면, 그 전에 만든 규칙이나 나중에 콘솔 권한이 생긴 역할의 규칙이 소속 변경 때 관리 역할을 준다.
 * 부여하는 순간에도 막아, 조직 단위 관리자가 소속을 바꿔 관리 역할을 얻는 길을 닫는다
 */
@Component
class ConsoleRoleGrantGuard(private val authorizer: AdminAuthorizer) : RoleGrantGuard {
    override fun check(request: GrantRequest) {
        if (request.sourceType !in RULE_SOURCES) return
        if (authorizer.isConsoleRole(request.roleId)) {
            throw BusinessRuleException("관리 콘솔 권한이 있는 역할은 조직·그룹 역할 규칙으로 줄 수 없습니다. 이 역할을 쓰는 규칙을 끄세요")
        }
    }

    private companion object {
        val RULE_SOURCES = setOf(AssignmentSourceType.ORGANIZATION, AssignmentSourceType.GROUP)
    }
}
