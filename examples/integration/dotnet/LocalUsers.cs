namespace Sample;

/// <summary>로컬 사용자. 실제 시스템은 사용자 테이블에 iam_subject_id 컬럼을 둔다</summary>
public sealed class LocalUser(long id, string? iamSubjectId, string? empNo, string? name)
{
    public long Id { get; } = id;
    public string? IamSubjectId { get; set; } = iamSubjectId;
    public string? EmpNo { get; } = empNo;
    public string? Name { get; set; } = name;
    public bool Enabled { get; set; } = true;
}

/// <summary>로컬 사용자 저장소 (예제라 메모리)</summary>
public sealed class LocalUsers
{
    private readonly List<LocalUser> _users = [];
    private long _seq;

    public LocalUsers()
    {
        // IAM 도입 전부터 있던 계정 (iam_subject_id 가 아직 없다). 첫 로그인 때 사번으로 연결된다
        _users.Add(new LocalUser(++_seq, null, "D-001", "기존 사용자"));
    }

    /// <summary>sub → 사번 → 새로 만들기(JIT) 순서로 찾는다. 이메일로는 연결하지 않는다</summary>
    public LocalUser Link(string sub, string? empNo, string? name)
    {
        lock (_users)
        {
            var user = _users.FirstOrDefault(u => u.IamSubjectId == sub)
                ?? _users.FirstOrDefault(u => u.IamSubjectId == null && empNo != null && u.EmpNo == empNo);
            if (user == null)
            {
                user = new LocalUser(++_seq, null, empNo, name);
                _users.Add(user);
            }
            user.IamSubjectId = sub;
            user.Name = name;
            return user;
        }
    }

    /// <summary>퇴사 처리: 계정을 끈다 (지우지 않는다)</summary>
    public void Disable(string sub)
    {
        lock (_users)
        {
            var user = _users.FirstOrDefault(u => u.IamSubjectId == sub);
            if (user != null) user.Enabled = false;
        }
    }
}
