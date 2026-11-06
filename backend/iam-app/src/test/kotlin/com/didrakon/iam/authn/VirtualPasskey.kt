package com.didrakon.iam.authn

import com.webauthn4j.data.AuthenticatorSelectionCriteria
import com.webauthn4j.data.PublicKeyCredentialCreationOptions
import com.webauthn4j.data.PublicKeyCredentialParameters
import com.webauthn4j.data.PublicKeyCredentialRequestOptions
import com.webauthn4j.data.PublicKeyCredentialRpEntity
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.PublicKeyCredentialUserEntity
import com.webauthn4j.data.ResidentKeyRequirement
import com.webauthn4j.data.UserVerificationRequirement
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.client.Origin
import com.webauthn4j.data.client.challenge.DefaultChallenge
import com.webauthn4j.test.authenticator.webauthn.NoneAttestationAuthenticator
import com.webauthn4j.test.authenticator.webauthn.WebAuthnAuthenticatorAdaptor
import com.webauthn4j.test.client.ClientPlatform
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import java.util.Base64

/**
 * 테스트용 브라우저 + 패스키 인증기 (webauthn4j 가상 인증기).
 * Spring 이 준 옵션 JSON 을 인증기에 넘기고, 인증기 응답을 Spring 이 받는 JSON(iam-login/passkey.js 가 보내는 모양)으로 만든다.
 * 등록한 패스키는 이 객체 안에 남는다 (기기 하나).
 */
class VirtualPasskey(origin: String = "http://localhost:8080") {
    private val client = ClientPlatform(Origin(origin), WebAuthnAuthenticatorAdaptor(NoneAttestationAuthenticator()))
    private val json = JsonMapper.builder().build()

    /** POST /webauthn/register 본문 */
    fun register(options: JsonNode, label: String): String {
        val user = options["user"]
        val creation = PublicKeyCredentialCreationOptions(
            PublicKeyCredentialRpEntity(options["rp"]["id"].stringValue(), options["rp"]["name"].stringValue()),
            PublicKeyCredentialUserEntity(decode(user["id"].stringValue()), user["name"].stringValue(), user["displayName"].stringValue()),
            DefaultChallenge(decode(options["challenge"].stringValue())),
            options["pubKeyCredParams"].values().map {
                PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.create(it["alg"].longValue()))
            },
            options["timeout"]?.longValue(),
            emptyList(),
            options["authenticatorSelection"].let {
                AuthenticatorSelectionCriteria(
                    null,
                    ResidentKeyRequirement.create(it["residentKey"].stringValue()),
                    UserVerificationRequirement.create(it["userVerification"].stringValue()),
                )
            },
            null,
            null,
            null,
        )
        val credential = client.create(creation)
        val response = credential.response ?: throw AssertionError("인증기 응답 없음")
        return json.writeValueAsString(
            mapOf(
                "publicKey" to mapOf(
                    "label" to label,
                    "credential" to mapOf(
                        "id" to credential.id,
                        "rawId" to encode(credential.rawId ?: throw AssertionError()),
                        "response" to mapOf(
                            "attestationObject" to encode(response.attestationObject),
                            "clientDataJSON" to encode(response.clientDataJSON),
                            "transports" to listOf("internal"),
                        ),
                        "type" to "public-key",
                        "clientExtensionResults" to emptyMap<String, Any>(),
                    ),
                ),
            ),
        )
    }

    /** POST /login/webauthn 본문 */
    fun authenticate(options: JsonNode): String {
        val request = PublicKeyCredentialRequestOptions(
            DefaultChallenge(decode(options["challenge"].stringValue())),
            options["timeout"]?.longValue(),
            options["rpId"].stringValue(),
            emptyList(),
            UserVerificationRequirement.create(options["userVerification"].stringValue()),
            null,
        )
        val credential = client.get(request)
        val response = credential.response ?: throw AssertionError("인증기 응답 없음")
        return json.writeValueAsString(
            mapOf(
                "id" to credential.id,
                "rawId" to encode(credential.rawId ?: throw AssertionError()),
                "response" to mapOf(
                    "authenticatorData" to encode(response.authenticatorData),
                    "clientDataJSON" to encode(response.clientDataJSON),
                    "signature" to encode(response.signature),
                    "userHandle" to response.userHandle?.let(::encode),
                ),
                "type" to "public-key",
                "clientExtensionResults" to emptyMap<String, Any>(),
            ),
        )
    }

    private fun decode(value: String): ByteArray = Base64.getUrlDecoder().decode(value)

    private fun encode(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
}
