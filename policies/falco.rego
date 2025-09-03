package falco
default allow = false
event_type(i) := et { et := i.output.fields.event_type }
event_type(i) := et { et := i.output_fields["evt.type"] }
prio := {"Emergency":0,"Alert":1,"Critical":2,"Error":3,"Warning":4,"Notice":5,"Informational":6,"Debug":7}
priority_num(i) := n { n := i.output.priority }
priority_num(i) := n { n := prio[i.priority] }
priority_num(i) := n { n := prio[i.output_fields["priority"]] }
allow { event_type(input) == "unexpected_process"; priority_num(input) >= 4 }
allow { priority_num(input) < 4 }
