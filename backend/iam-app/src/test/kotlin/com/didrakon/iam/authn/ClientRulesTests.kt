package com.didrakon.iam.authn

import com.didrakon.iam.authn.client.ClientLoginChange
import com.didrakon.iam.authn.client.ClientRegistration
import com.didrakon.iam.authn.client.ClientType
import com.didrakon.iam.authn.client.SsoClientService
import com.didrakon.iam.authz.AuthzTest
import com.didrakon.iam.common.error.BusinessRuleException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.beans.factory.annotation.Autowired

/** SSO 클라이언트 등록 규칙: redirect 주소 스킴, 시스템 전용 scope. 테스트마다 롤백된다 */
@AuthzTest
class ClientRulesTests @Autowired constructor(
    private val clientService: SsoClientService,
) {
    @Test
    fun `redirect 주소에는 스크립트 스킴을 쓸 수 없고 웹 클라이언트는 http·https 만 받는다`() {
        listOf("javascript:alert(1)", "data:text/html,x", "file:///etc/passwd").forEach { uri ->
            assertThrows<BusinessRuleException> { register(ClientType.MOBILE, redirect = uri) }
        }
        assertThrows<BusinessRuleException> { register(ClientType.WEB, redirect = "com.example.app:/callback") }

        register(ClientType.WEB, redirect = "https://app.example.com/callback")
        register(ClientType.WEB, redirect = "http://localhost:3000/callback")
        register(ClientType.MOBILE, redirect = "com.example.app:/callback")
    }

    @Test
    fun `등록 뒤 주소를 바꿀 때도 같은 스킴 규칙을 적용한다`() {
        val client = register(ClientType.WEB, redirect = "https://app.example.com/callback")

        assertThrows<BusinessRuleException> {
            clientService.update(
                client.ssoClient.requireId(), "앱", requireMfa = false, backchannelLogoutUri = null,
                loginChange = ClientLoginChange(postLogoutRedirectUris = setOf("javascript:alert(1)")),
            )
        }
    }

    @Test
    fun `시스템 전용 scope 는 사용자 로그인 클라이언트에 줄 수 없고 시스템 클라이언트에는 준다`() {
        assertThrows<BusinessRuleException> { register(ClientType.WEB, redirect = "https://app.example.com/cb", scopes = setOf("iam.authz.check")) }
        assertThrows<BusinessRuleException> { register(ClientType.MOBILE, redirect = "com.example.app:/cb", scopes = setOf("iam.hr.sync")) }

        clientService.register(ClientRegistration("batch-${System.nanoTime()}", "배치", ClientType.BATCH, scopes = setOf("iam.hr.sync")))
    }

    private fun register(type: ClientType, redirect: String, scopes: Set<String> = emptySet()) =
        clientService.register(ClientRegistration("c-${System.nanoTime()}", "앱", type, redirectUris = setOf(redirect), scopes = scopes))
}
