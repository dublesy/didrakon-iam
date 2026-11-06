plugins {
    alias(libs.plugins.kotlin.jpa)
    alias(libs.plugins.ksp)
}

dependencies {
    // audit 는 다른 모듈의 이벤트를 받아 기록하는 맨 끝 소비자다. 다른 모듈은 audit 에 의존하지 않는다
    api(project(":iam-authn"))
    api(project(":iam-governance"))
    implementation(project(":iam-risk"))
    implementation("tools.jackson.core:jackson-databind")
}
