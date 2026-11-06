package com.didrakon.iam.identity.subject

import java.time.LocalDate
import org.springframework.data.domain.Page
import org.springframework.data.domain.Pageable
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param

interface SubjectRepository : JpaRepository<Subject, Long>

interface UserRepository : JpaRepository<User, Long> {
    fun findByEmpNo(empNo: String): User?

    fun findByEmpNoIn(empNos: Collection<String>): List<User>

    /** [lowerEmails] 는 소문자로 넘긴다 (대소문자 무시) */
    @Query("select u from User u where lower(u.email) in :lowerEmails")
    fun findByLowerEmailIn(@Param("lowerEmails") lowerEmails: Collection<String>): List<User>

    fun existsByUserKindAndEmail(userKind: UserKind, email: String): Boolean

    fun findByStatusIn(statuses: Collection<SubjectStatus>): List<User>

    /**
     * 이름·사번·이메일 부분 일치. 검색어가 없으면 전체. [kind] 가 있으면 그 구분만.
     * [restrictOrgs] 면 활성 PRIMARY 소속 조직이 [orgIds] 안인 사용자만 (조직 단위 관리자의 목록)
     */
    @Query(
        """
        select u from User u
        where (:q is null or lower(u.name) like lower(concat('%', :q, '%')) or u.empNo like concat('%', :q, '%')
               or lower(u.email) like lower(concat('%', :q, '%')))
          and (:kind is null or u.userKind = :kind)
          and (:restrictOrgs = false or exists (
                select 1 from SubjectOrganization m
                where m.subjectId = u.id and m.validUntil is null and m.orgId in :orgIds
                  and m.membershipType = com.didrakon.iam.identity.organization.MembershipType.PRIMARY))
        """,
    )
    fun search(
        @Param("q") q: String?,
        @Param("kind") kind: UserKind?,
        @Param("restrictOrgs") restrictOrgs: Boolean,
        @Param("orgIds") orgIds: Collection<Long>,
        pageable: Pageable,
    ): Page<User>

    /** 퇴사 예정일이 지났는데 아직 퇴사 처리되지 않은 사용자 */
    @Query("select u from User u where u.retireDate <= :today and u.status <> com.didrakon.iam.identity.subject.SubjectStatus.RETIRED")
    fun findRetireDue(@Param("today") today: LocalDate): List<User>
}
