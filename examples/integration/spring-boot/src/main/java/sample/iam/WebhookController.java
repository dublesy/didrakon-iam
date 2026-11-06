package sample.iam;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * IAM 웹훅 수신. 서명 → 시각 → 중복 순서로 거른 뒤 처리한다.
 */
@RestController
public class WebhookController {

    private static final long MAX_AGE_SECONDS = 300;

    private final byte[] secret;
    private final ObjectMapper json;
    private final LocalUsers users;
    private final SessionIndex sessions;
    /** 처리한 전달 ID. 예제라 메모리에 둔다. 실제로는 DB 테이블(전달 ID 에 unique)에 둔다 */
    private final Set<String> processed = ConcurrentHashMap.newKeySet();

    public WebhookController(@Value("${webhook.secret}") String secret, ObjectMapper json,
                             LocalUsers users, SessionIndex sessions) {
        this.secret = secret.getBytes(StandardCharsets.UTF_8);
        this.json = json;
        this.users = users;
        this.sessions = sessions;
    }

    /** 본문은 byte[] 로 받는다. 객체로 받아 다시 직렬화하면 서명이 맞지 않는다 */
    @PostMapping("/webhooks/iam")
    ResponseEntity<Map<String, Object>> receive(@RequestBody byte[] body,
                                                @RequestHeader("X-Didrakon-Delivery") String delivery,
                                                @RequestHeader("X-Didrakon-Timestamp") String timestamp,
                                                @RequestHeader("X-Didrakon-Signature") String signature) throws IOException {
        if (!validSignature(timestamp, body, signature)) {
            return ResponseEntity.status(401).body(Map.of("error", "bad signature"));
        }
        if (!fresh(timestamp)) {
            return ResponseEntity.status(401).body(Map.of("error", "stale timestamp"));
        }
        if (!processed.add(delivery)) {
            return ResponseEntity.ok(Map.of("duplicate", true));
        }

        JsonNode event = json.readTree(body);
        if ("user.status_changed".equals(event.path("type").asText())
                && "RETIRED".equals(event.path("data").path("status").asText())) {
            String sub = event.path("data").path("subjectId").asText();
            users.disable(sub);                 // 계정 끄기 (권한 회수는 시스템마다)
            sessions.end(sub, null);            // 그 사람의 세션 모두 종료
        }
        return ResponseEntity.ok(Map.of("ok", true));
    }

    private boolean validSignature(String timestamp, byte[] body, String signature) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            mac.update((timestamp + ".").getBytes(StandardCharsets.UTF_8));
            String expected = "sha256=" + HexFormat.of().formatHex(mac.doFinal(body));
            // 상수 시간 비교
            return MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                    signature.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean fresh(String timestamp) {
        try {
            long age = System.currentTimeMillis() / 1000 - Long.parseLong(timestamp);
            return Math.abs(age) <= MAX_AGE_SECONDS;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
