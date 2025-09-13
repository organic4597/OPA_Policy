package falco.authz

# 결과 스키마: 항상 동일 구조로 반환
default outcome := "access"
default allow := true

# 경고 레벨
outcome := "warning" {
  input.rule.level == "warning"
}
# 차단 레벨(deny)
outcome := "deny" {
  input.rule.level == "critical"
}

# allow 여부(예: access만 true)
allow {
  outcome == "access"
}

# 표준 결과 (OPA에서 /v1/data/falco/authz/result 로 평가)
result := {
  "decision": allow,
  "outcome": outcome,                # "access" | "warning" | "deny"
  "reason": sprintf("rule=%v proc=%v", [input.rule.name, input.process.name]),
  # Ziti 처분용 식별 정보(반드시 input에 들어오게 Log/Collector 단계에서 맵핑)
  "identity_id": input.identity_id,  # ziti identity id 또는 name
  "service_name": input.service,     # (선택) 연관 서비스명
  "ts": time.now_ns(),
}

