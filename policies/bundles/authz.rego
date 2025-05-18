package bundles.authz

default allow = false

allow {
  if input.user == "admin"
}

allow {
  if input.user == "alice"
  if input.action == "read"
}
