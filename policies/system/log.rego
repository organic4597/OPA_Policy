package system.log

# deny가 아닌 모든 결정 로그 드롭(원격 전송 안 함)
drop {
  not input.result.outcome == "deny"
}

