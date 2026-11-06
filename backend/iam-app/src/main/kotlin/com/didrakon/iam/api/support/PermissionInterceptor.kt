package com.didrakon.iam.api.support

import com.didrakon.iam.authz.decision.OrgReach
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.web.method.HandlerMethod
import org.springframework.web.servlet.HandlerInterceptor
import org.springframework.web.servlet.HandlerMapping
import org.springframework.web.servlet.config.annotation.InterceptorRegistry
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer

/**
 * /api 인가. 핸들러에 [RequiresPermission] 이 있으면 IAM 의 PDP 로 판정하고, [SelfService] 면 본인 subject 만 확인한다.
 * 둘 다 없는 API 는 거부한다 (빠뜨린 인가 설정이 열린 API 가 되지 않도록).
 *
 * [RequiresPermission.orgOf] 로 대상 조직을 찾아 PDP 에 넘기므로, ORGANIZATION 범위로 받은 권한(조직 단위 관리자)은
 * 그 범위 안의 사용자·조직·소속·세션에만 통한다. 대상이 사람이고 바꾸는 요청이면 [AdminAuthorizer.guardAdminTarget] 도 거친다.
 */
@Component
class PermissionInterceptor(private val authorizer: AdminAuthorizer) : HandlerInterceptor {
    override fun preHandle(request: HttpServletRequest, response: HttpServletResponse, handler: Any): Boolean {
        if (handler !is HandlerMethod) return true
        if (handler.hasMethodAnnotation(SelfService::class.java)) {
            authorizer.requireActiveSubject(ApiPrincipal.requireSubjectId())
            return true
        }
        val required = handler.getMethodAnnotation(RequiresPermission::class.java)
            ?: throw ApiException(HttpStatus.FORBIDDEN, "FORBIDDEN", "권한이 설정되지 않은 API 입니다")
        if (required.scope.isNotEmpty() && ApiPrincipal.hasScope(required.scope)) return true

        ApiPrincipal.requireSubjectId()
        val target = when (required.orgOf) {
            OrgTarget.NONE -> ResolvedTarget(null, null)
            // 권한이 닿는 조직 하나로 판정해 MFA 같은 정책도 그대로 적용한다. 범위 밖 항목은 핸들러가 거른다
            OrgTarget.ANY -> when (val reach = authorizer.reach(required.resource, required.action)) {
                is OrgReach.Orgs -> ResolvedTarget(reach.orgIds.minOrNull(), null)
                OrgReach.All -> ResolvedTarget(null, null)
            }
            else -> authorizer.resolve(required.orgOf, pathValue(request, required.orgOf))
        }
        authorizer.authorize(required.resource, required.action, target.orgId, request.remoteAddr)
        target.subjectId?.let { authorizer.guardAdminTarget(required.resource, required.action, it) }
        return true
    }

    private fun pathValue(request: HttpServletRequest, target: OrgTarget): Long? {
        val name = target.pathVariable ?: return null
        @Suppress("UNCHECKED_CAST")
        val variables = request.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE) as? Map<String, String>
        return variables?.get(name)?.toLongOrNull()
    }
}

@Configuration
class ApiWebConfig(private val permissionInterceptor: PermissionInterceptor) : WebMvcConfigurer {
    override fun addInterceptors(registry: InterceptorRegistry) {
        registry.addInterceptor(permissionInterceptor).addPathPatterns("/api/**")
    }
}
