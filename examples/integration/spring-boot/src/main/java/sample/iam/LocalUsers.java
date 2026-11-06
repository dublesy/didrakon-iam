package sample.iam;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.stereotype.Component;

/**
 * 로컬 사용자 저장소 (예제라 메모리). 실제 시스템은 사용자 테이블에 iam_subject_id 컬럼을 둔다.
 */
@Component
public class LocalUsers {

    public static final class LocalUser {
        final long id;
        volatile String iamSubjectId;
        final String empNo;
        volatile String name;
        volatile boolean enabled = true;

        LocalUser(long id, String iamSubjectId, String empNo, String name) {
            this.id = id;
            this.iamSubjectId = iamSubjectId;
            this.empNo = empNo;
            this.name = name;
        }
    }

    private final AtomicLong seq = new AtomicLong();
    private final Map<Long, LocalUser> users = new ConcurrentHashMap<>();

    public LocalUsers() {
        // IAM 도입 전부터 있던 계정 (iam_subject_id 가 아직 없다). 첫 로그인 때 사번으로 연결된다
        save(new LocalUser(seq.incrementAndGet(), null, "D-001", "기존 사용자"));
    }

    /** sub → 사번 → 새로 만들기(JIT) 순서로 찾는다. 이메일로는 연결하지 않는다 */
    public synchronized LocalUser link(String sub, String empNo, String name) {
        LocalUser user = findBySubject(sub)
                .or(() -> findUnlinkedByEmpNo(empNo))
                .orElseGet(() -> save(new LocalUser(seq.incrementAndGet(), null, empNo, name)));
        user.iamSubjectId = sub;
        user.name = name;
        return user;
    }

    /** 퇴사 처리: 계정을 끈다 (지우지 않는다) */
    public void disable(String sub) {
        findBySubject(sub).ifPresent(u -> u.enabled = false);
    }

    public Optional<LocalUser> findBySubject(String sub) {
        return users.values().stream().filter(u -> Objects.equals(u.iamSubjectId, sub)).findFirst();
    }

    private Optional<LocalUser> findUnlinkedByEmpNo(String empNo) {
        if (empNo == null) return Optional.empty();
        return users.values().stream()
                .filter(u -> u.iamSubjectId == null && empNo.equals(u.empNo))
                .findFirst();
    }

    private LocalUser save(LocalUser user) {
        users.put(user.id, user);
        return user;
    }
}
