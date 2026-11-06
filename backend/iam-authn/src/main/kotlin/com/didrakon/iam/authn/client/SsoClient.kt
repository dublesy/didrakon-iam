package com.didrakon.iam.authn.client

import com.didrakon.iam.common.jpa.BaseCreatedEntity
import com.didrakon.iam.common.jpa.IdEntity
import com.didrakon.iam.common.jpa.idEquals
import com.didrakon.iam.common.jpa.idHashCode
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.Table
import org.springframework.data.jpa.repository.JpaRepository

/** SSO 로 연결된 시스템. 비밀값·redirect URI 등 프로토콜 설정은 SAS 의 oauth2_registered_client 에 있다 */
@Entity
@Table(name = "sso_client")
class SsoClient(
    registeredClientId: String,
    clientCode: String,
    clientName: String,
    clientType: ClientType,
    requireMfa: Boolean = false,
) : BaseCreatedEntity(), IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "client_id")
    override val id: Long? = null

    /** oauth2_registered_client.id */
    @Column(name = "registered_client_id", nullable = false, length = 100, updatable = false)
    val registeredClientId: String = registeredClientId

    /** OAuth2 client_id 로도 쓴다 */
    @Column(name = "client_code", nullable = false, length = 100, updatable = false)
    val clientCode: String = clientCode

    @Column(name = "client_name", nullable = false, length = 200)
    var clientName: String = clientName
        protected set

    @Enumerated(EnumType.STRING)
    @Column(name = "client_type", nullable = false, length = 30, updatable = false)
    val clientType: ClientType = clientType

    @Enumerated(EnumType.STRING)
    @Column(name = "protocol", nullable = false, length = 30, updatable = false)
    val protocol: ClientProtocol = ClientProtocol.OIDC

    /** 이 클라이언트로 로그인할 때 MFA 필수 */
    @Column(name = "require_mfa", nullable = false)
    var requireMfa: Boolean = requireMfa
        protected set

    /** OIDC Back-Channel Logout 수신 주소. 로그인 세션이 끝나면 로그아웃 토큰을 보낸다 */
    @Column(name = "backchannel_logout_uri", length = 500)
    var backchannelLogoutUri: String? = null
        protected set

    /** Supabase Third-Party Auth 용: 이 클라이언트에 주는 토큰에 role = "authenticated" 를 넣는다 */
    @Column(name = "supabase_role_claim", nullable = false)
    var supabaseRoleClaim: Boolean = false
        protected set

    /** 앱 런처 시작 주소. 있으면 IAM 홈의 내 앱 목록에 나온다 */
    @Column(name = "home_url", length = 500)
    var homeUrl: String? = null
        protected set

    @Column(name = "is_active", nullable = false)
    var isActive: Boolean = true
        protected set

    internal fun update(clientName: String, requireMfa: Boolean, backchannelLogoutUri: String?, supabaseRoleClaim: Boolean, homeUrl: String?) {
        this.clientName = clientName
        this.requireMfa = requireMfa
        this.backchannelLogoutUri = backchannelLogoutUri
        this.supabaseRoleClaim = supabaseRoleClaim
        this.homeUrl = homeUrl
    }

    internal fun changeActive(active: Boolean) {
        isActive = active
    }

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

/** WEB·MOBILE = 사용자 로그인(authorization code), API·BATCH = 시스템 간 호출(client credentials) */
enum class ClientType { WEB, API, MOBILE, BATCH }

enum class ClientProtocol { OIDC, SAML }

interface SsoClientRepository : JpaRepository<SsoClient, Long> {
    fun findByClientCode(clientCode: String): SsoClient?

    fun findByRegisteredClientId(registeredClientId: String): SsoClient?
}
