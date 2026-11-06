package com.didrakon.iam.identity.hr

import com.didrakon.iam.common.jpa.IdEntity
import com.didrakon.iam.common.jpa.idEquals
import com.didrakon.iam.common.jpa.idHashCode
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.Table
import org.springframework.data.jpa.repository.JpaRepository
import java.time.Instant

/** HR 연동 한 번의 실행 기록. 만든 뒤 바꾸지 않는다 */
@Entity
@Table(name = "hr_sync_run")
class HrSyncRun(
    dryRun: Boolean,
    startedAt: Instant,
    finishedAt: Instant,
    actorSubjectId: Long?,
    total: Int,
    summary: String,
    errors: String,
    missingCount: Int?,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "run_id")
    override val id: Long? = null

    @Column(name = "dry_run", nullable = false, updatable = false)
    val dryRun: Boolean = dryRun

    @Column(name = "started_at", nullable = false, updatable = false)
    val startedAt: Instant = startedAt

    @Column(name = "finished_at", nullable = false, updatable = false)
    val finishedAt: Instant = finishedAt

    @Column(name = "actor_subject_id", updatable = false)
    val actorSubjectId: Long? = actorSubjectId

    @Column(name = "total", nullable = false, updatable = false)
    val total: Int = total

    /** 처리 결과별 레코드 수 (JSON 객체) */
    @Column(name = "summary", nullable = false, updatable = false, columnDefinition = "json")
    val summary: String = summary

    /** 오류 레코드 앞 [HrSyncService.MAX_STORED_ERRORS] 건 (JSON 배열) */
    @Column(name = "errors", nullable = false, updatable = false, columnDefinition = "json")
    val errors: String = errors

    @Column(name = "missing_count", updatable = false)
    val missingCount: Int? = missingCount

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

interface HrSyncRunRepository : JpaRepository<HrSyncRun, Long> {
    fun findTop50ByOrderByIdDesc(): List<HrSyncRun>
}
