package falco

# 기본값(권장 표기)
default allow := false

# Falco의 문자열 우선순위를 정수로 매핑
sev_order := {
  "Emergency": 7,
  "Alert": 6,
  "Critical": 5,
  "Error": 4,
  "Warning": 3,
  "Notice": 2,
  "Informational": 1,
  "Debug": 0,
}

# 편의 바인딩: 이벤트 타입 (Falco json_output의 output_fields 내 "evt.type")
event_type := input.output_fields["evt.type"]

# 편의 바인딩: 숫자 우선순위
priority_num := sev_order[input.priority]

# (a) event_type == "unexpected_process" 이고 우선순위 >= 4 이면 허용
allow if {
  event_type == "unexpected_process"
  priority_num >= 4
}

# (b) 우선순위 < 4 이면 허용
allow if {
  priority_num < 4
}
