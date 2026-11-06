package sample.iam;

import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionListener;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * 서버 세션을 IAM sub·sid 로 찾을 수 있게 둔 색인.
 * back-channel 로그아웃과 퇴사 웹훅이 이 색인으로 남의 세션을 끝낸다.
 * 서버가 여러 대면 Spring Session(JDBC·Redis)의 세션 저장소에 sub·sid 를 함께 저장해 같은 일을 한다.
 */
@Component
public class SessionIndex implements HttpSessionListener {

    public static final String SUB = "iam.sub";
    public static final String SID = "iam.sid";

    private final Map<String, HttpSession> sessions = new ConcurrentHashMap<>();

    /** 로그인 성공 때 부른다 */
    public void register(HttpSession session, String sub, String sid) {
        session.setAttribute(SUB, sub);
        session.setAttribute(SID, sid);
        sessions.put(session.getId(), session);
    }

    /** sid 가 있으면 그 로그인 세션만, 없으면 sub 의 세션을 모두 끝낸다. 끝낸 수를 돌려준다 */
    public int end(String sub, String sid) {
        List<HttpSession> targets = sessions.values().stream()
                .filter(s -> sid != null ? sid.equals(attr(s, SID)) : Objects.equals(sub, attr(s, SUB)))
                .toList();
        targets.forEach(s -> {
            sessions.remove(s.getId());
            try {
                s.invalidate();
            } catch (IllegalStateException alreadyInvalid) {
                // 그 사이 끝난 세션
            }
        });
        return targets.size();
    }

    @Override
    public void sessionDestroyed(HttpSessionEvent event) {
        sessions.remove(event.getSession().getId());
    }

    private static Object attr(HttpSession s, String name) {
        try {
            return s.getAttribute(name);
        } catch (IllegalStateException invalidated) {
            return null;
        }
    }
}
