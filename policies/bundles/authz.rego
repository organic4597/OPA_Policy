package falco

default allow = false

allow {
  input.output.fields.event_type == "unexpected_process"
  input.output.priority >= 4
}

allow {
  input.output.priority < 4
}