package com.didrakon.iam.api.risk

import com.didrakon.iam.api.support.ApiResources
import com.didrakon.iam.api.support.ApiResponse
import com.didrakon.iam.api.support.RequiresPermission
import com.didrakon.iam.authz.role.PermissionAction
import com.didrakon.iam.common.RiskLevel
import com.didrakon.iam.risk.RiskAction
import com.didrakon.iam.risk.RiskAssessment
import com.didrakon.iam.risk.RiskPolicy
import com.didrakon.iam.risk.RiskPolicyService
import com.didrakon.iam.risk.RiskPolicySpec
import com.didrakon.iam.risk.RiskSignal
import com.didrakon.iam.risk.RiskSignalType
import com.didrakon.iam.risk.RiskType
import jakarta.validation.Valid
import jakarta.validation.constraints.Max
import jakarta.validation.constraints.Min
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController
import java.time.Instant

data class RiskPolicyResponse(
    val riskPolicyId: Long,
    val policyName: String,
    val riskType: RiskType,
    val conditionExpression: String,
    val riskScore: Int,
    val action: RiskAction,
    val isActive: Boolean,
) {
    companion object {
        fun from(p: RiskPolicy) = RiskPolicyResponse(p.requireId(), p.policyName, p.riskType, p.conditionExpression, p.riskScore, p.action, p.isActive)
    }
}

data class CreateRiskPolicyRequest(
    val riskType: RiskType,
    @field:NotBlank @field:Size(max = 200) val policyName: String,
    @field:NotBlank @field:Size(max = 2000) val conditionExpression: String,
    @field:Min(0) @field:Max(100) val riskScore: Int,
    val action: RiskAction,
) {
    fun spec() = RiskPolicySpec(policyName, conditionExpression, riskScore, action)
}

/** 평가 대상(risk_type)은 바꿀 수 없다. 바꾸려면 새 정책을 만든다 */
data class UpdateRiskPolicyRequest(
    @field:NotBlank @field:Size(max = 200) val policyName: String,
    @field:NotBlank @field:Size(max = 2000) val conditionExpression: String,
    @field:Min(0) @field:Max(100) val riskScore: Int,
    val action: RiskAction,
) {
    fun spec() = RiskPolicySpec(policyName, conditionExpression, riskScore, action)
}

data class RiskAssessmentResponse(
    val assessmentId: Long,
    val requestId: Long?,
    val riskScore: Int,
    val riskLevel: RiskLevel,
    val decision: RiskAction,
    val assessedAt: Instant,
) {
    companion object {
        fun from(a: RiskAssessment) = RiskAssessmentResponse(a.requireId(), a.requestId, a.riskScore, a.riskLevel, a.decision, a.assessedAt)
    }
}

data class RiskSignalResponse(val riskSignalId: Long, val signalType: RiskSignalType, val riskScore: Int, val details: String?, val detectedAt: Instant) {
    companion object {
        fun from(s: RiskSignal) = RiskSignalResponse(s.requireId(), s.signalType, s.riskScore, s.details, s.detectedAt)
    }
}

data class SubjectRiskResponse(val assessments: List<RiskAssessmentResponse>, val signals: List<RiskSignalResponse>)

@RestController
@RequestMapping("/api/v1")
class RiskApi(private val riskPolicyService: RiskPolicyService) {
    @GetMapping("/risk-policies")
    @RequiresPermission(ApiResources.RISK, PermissionAction.READ)
    fun policies() = ApiResponse.ok(riskPolicyService.policies().map(RiskPolicyResponse::from))

    @PostMapping("/risk-policies")
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresPermission(ApiResources.RISK, PermissionAction.CREATE)
    fun create(@Valid @RequestBody r: CreateRiskPolicyRequest) =
        ApiResponse.ok(RiskPolicyResponse.from(riskPolicyService.create(r.riskType, r.spec())))

    @PutMapping("/risk-policies/{policyId}")
    @RequiresPermission(ApiResources.RISK, PermissionAction.UPDATE)
    fun update(@PathVariable policyId: Long, @Valid @RequestBody r: UpdateRiskPolicyRequest) =
        ApiResponse.ok(RiskPolicyResponse.from(riskPolicyService.update(policyId, r.spec())))

    @PostMapping("/risk-policies/{policyId}/activate")
    @RequiresPermission(ApiResources.RISK, PermissionAction.UPDATE)
    fun activate(@PathVariable policyId: Long) = ApiResponse.ok(RiskPolicyResponse.from(riskPolicyService.changeActive(policyId, true)))

    @PostMapping("/risk-policies/{policyId}/deactivate")
    @RequiresPermission(ApiResources.RISK, PermissionAction.UPDATE)
    fun deactivate(@PathVariable policyId: Long) = ApiResponse.ok(RiskPolicyResponse.from(riskPolicyService.changeActive(policyId, false)))

    /** 최근 평가·신호 각 20건 */
    @GetMapping("/subjects/{subjectId}/risk")
    @RequiresPermission(ApiResources.RISK, PermissionAction.READ)
    fun subjectRisk(@PathVariable subjectId: Long) = ApiResponse.ok(
        SubjectRiskResponse(
            riskPolicyService.recentAssessments(subjectId).map(RiskAssessmentResponse::from),
            riskPolicyService.recentSignals(subjectId).map(RiskSignalResponse::from),
        ),
    )
}
