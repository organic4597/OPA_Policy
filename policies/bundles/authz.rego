package bundles.authz

default allow = false

allow {
  input.user == "admin"
}

allow {
  input.user == "alice"
  input.action == "read"
}

}
