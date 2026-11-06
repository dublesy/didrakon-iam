package sample.iam;

import jakarta.servlet.http.HttpSession;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MeController {

    /** 로그인하지 않았으면 SecurityConfig 의 진입점이 401 을 준다 */
    @GetMapping("/me")
    Map<String, Object> me(@AuthenticationPrincipal OidcUser user, HttpSession session) {
        List<String> roles = user.getClaimAsStringList("roles");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("sub", user.getSubject());
        body.put("name", user.getFullName());
        body.put("empNo", user.getClaimAsString("emp_no"));
        body.put("roles", roles == null ? List.of() : roles);
        body.put("localUserId", session.getAttribute("localUserId"));
        body.put("sid", user.getClaimAsString("sid"));
        return body;
    }
}
