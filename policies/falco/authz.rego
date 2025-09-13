package falco.authz

default outcome := "access"
default allow := true

# 경고/거부는 if 구문 사용
outcome := "warning" if input.rule.level == "warning"
outcome := "deny"    if input.rule.level == "critical"

# allow 여부
allow if outcome == "access"

# 표준 결과
result := {
  "decision":    allow,
  "outcome":     outcome,  # "access" | "warning" | "deny"
  "reason":      sprintf("rule=%v proc=%v", [input.rule.name, input.process.name]),
  "identity_id": input.identity_id,
  "service_name": input.service,
  "ts":          time.now_ns(),
}

