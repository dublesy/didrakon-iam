package com.didrakon.iam.api.identity

import com.didrakon.iam.api.support.ApiPrincipal
import com.didrakon.iam.api.support.ApiResources
import com.didrakon.iam.api.support.ApiResponse
import com.didrakon.iam.api.support.RequiresPermission
import com.didrakon.iam.authz.role.PermissionAction
import com.didrakon.iam.config.BootstrapProperties
import com.didrakon.iam.identity.hr.HrEmployeeRecord
import com.didrakon.iam.identity.hr.HrSyncResult
import com.didrakon.iam.identity.hr.HrSyncRunView
import com.didrakon.iam.identity.hr.HrSyncService
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.time.LocalDate

/** 인사 시스템이 보내는 직원 한 명. 형식 오류는 요청 전체가 아니라 그 레코드의 오류로 돌려준다 */
data class HrEmployeeRequest(
    val empNo: String? = null,
    val name: String? = null,
    val email: String? = null,
    val phone: String? = null,
    val hireDate: LocalDate? = null,
    val orgCode: String? = null,
    val jobTitle: String? = null,
    val jobGrade: String? = null,
    val isManager: Boolean? = null,
    /** EMPLOYED, LEAVE, RETIRED */
    val employmentStatus: String? = null,
    val retireDate: LocalDate? = null,
) {
    fun toRecord() = HrEmployeeRecord(empNo, name, email, phone, hireDate, orgCode, jobTitle, jobGrade, isManager, employmentStatus, retireDate)
}

data class HrSyncRequest(
    val employees: List<HrEmployeeRequest>,
    /** true 면 피드에 없는 사용 중 사용자를 알려준다 (퇴사 처리는 하지 않는다) */
    val reportMissing: Boolean = false,
)

/**
 * HR 연동. 인사 시스템을 원본으로 입사·이동·휴직·퇴사를 맞춘다.
 * 인사 시스템은 `iam.hr.sync` scope 의 client credentials 토큰이나, IAM_HR_SYNC 역할 서비스 계정의 API 키로 부른다.
 */
@RestController
@RequestMapping("/api/v1/hr")
class HrSyncApi(
    private val hrSyncService: HrSyncService,
    private val bootstrapProperties: BootstrapProperties,
) {
    /** dryRun 은 반드시 지정한다 (빠뜨려 실제로 반영되는 일이 없도록). true 면 결과만 계산하고 반영하지 않는다 */
    @PostMapping("/sync")
    @RequiresPermission(ApiResources.HR_SYNC, PermissionAction.EXECUTE, scope = ApiResources.HR_SYNC_SCOPE)
    fun sync(@RequestParam dryRun: Boolean, @RequestBody request: HrSyncRequest): ApiResponse<HrSyncResult> = ApiResponse.ok(
        hrSyncService.sync(
            employees = request.employees.map { it.toRecord() },
            dryRun = dryRun,
            reportMissing = request.reportMissing,
            excludedEmpNos = setOf(bootstrapProperties.adminEmpNo),
            actorSubjectId = ApiPrincipal.subjectId(),
        ),
    )

    /** 최근 실행 50건 (최신순) */
    @GetMapping("/sync-runs")
    @RequiresPermission(ApiResources.HR_SYNC, PermissionAction.READ, scope = ApiResources.HR_SYNC_SCOPE)
    fun runs(): ApiResponse<List<HrSyncRunView>> = ApiResponse.ok(hrSyncService.recentRuns())
}
