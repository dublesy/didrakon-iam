package com.didrakon.iam.identity.group

import org.springframework.data.jpa.repository.JpaRepository

interface UserGroupRepository : JpaRepository<UserGroup, Long> {
    fun findByGroupCode(groupCode: String): UserGroup?
}

interface GroupMemberRepository : JpaRepository<GroupMember, GroupMemberId> {
    fun findByIdSubjectId(subjectId: Long): List<GroupMember>

    fun findByIdGroupId(groupId: Long): List<GroupMember>
}
