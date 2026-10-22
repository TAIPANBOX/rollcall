# Registry check

Checked for Task 1 of the v1 plan against the live IANA registries.

## UDP and TCP port 7431

Result: assigned. Port 7431 is not unassigned, so the plan is not changed by this check (see the ruling for Task 1).

- Service `pmd`, 7431/tcp, description "OpenView DM ovc/xmpv3 api pipe".
- Service `pmd`, 7431/udp, same description.
- Ports 7432-7436 are listed as Unassigned.

Source: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv (the registry page, https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml, shows Last Updated 2026-10-20).

@measured `curl -sS -f https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv | grep ',7431,'` 2026-10-22

## IPv6 multicast group ff02::114

Result: listed as "any private experiment" in the variable-scope table, so the group is available for private use.

- The entry `FF0X:0:0:0:0:0:0:114` reads "any private experiment"; `ff02::114` is its link-local (scope 2) form.
- The link-local table labels the range `FF02:0:0:0:0:0:0:100` to `FF02:0:0:0:0:0:0:178` "variable scope allocation" and has no separate row for 114.

Source: https://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xhtml (Last Updated 2026-04-07).

@measured `curl -sSL https://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xhtml | grep -n 'private experiment'` 2026-10-22
