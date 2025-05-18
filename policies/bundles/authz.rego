package example.authz

default allow = false

allow {
    input.method = "GET"
    input.path = [ "public" ]
}

allow {
    input.method = "GET"
    input.user = "admin"
}
