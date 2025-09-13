package system.log

# deny가 아닌 결정 로그는 드롭
drop if not input.result.outcome == "deny"

