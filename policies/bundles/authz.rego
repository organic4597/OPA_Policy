package bundles.authz

# 기본적으로 모든 요청을 거부하는 규칙
default allow = false

# allow 규칙: input.user가 "alice"면 허용
allow {
    input.user == "alice"
}

# 예시: 특정 경로 접근 권한 체크
allow {
    input.user == "bob"
    input.path == "/public"
}

# 예시: 관리자인 경우 모든 경로 허용
allow {
    input.user == "admin"
}
