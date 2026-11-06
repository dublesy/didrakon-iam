// 로컬 사용자 저장소 (예제라 메모리). 실제 시스템은 users 테이블에 iam_subject_id 컬럼을 둔다
const users = [
  // 이미 있던 계정: 첫 로그인 때 사번으로 연결된다
  { id: 1, empNo: 'D-001', name: '기존 사용자', iamSubjectId: null, active: true },
];

/** IAM sub 로 찾고, 없으면 사번으로 찾아 연결하고, 그래도 없으면 만든다(JIT) */
export function linkAccount(claims) {
  const sub = String(claims.sub);
  let user = users.find((u) => u.iamSubjectId === sub);
  if (!user && claims.emp_no) {
    user = users.find((u) => u.iamSubjectId === null && u.empNo === claims.emp_no);
    if (user) user.iamSubjectId = sub;
  }
  if (!user) {
    user = { id: users.length + 1, empNo: claims.emp_no ?? null, name: claims.name ?? '', iamSubjectId: sub, active: true };
    users.push(user);
  }
  return user;
}

export const findBySubject = (sub) => users.find((u) => u.iamSubjectId === String(sub));
