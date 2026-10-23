# Registry check

Checked on 2026-10-22 against the IANA registries.

## Decision

rollcall uses port 7432 (UDP and TCP). 7431 is assigned to pmd; 7432-7436 are unassigned.

`@claude` 2026-10-22: plan decision, recorded by commit bf465c8 (docs(plan): use port 7432; 7431 is IANA-assigned). The measured lines below are the facts it rests on.

## UDP and TCP port 7431

Result: assigned to `pmd` for TCP and UDP, with the description "OpenView DM ovc/xmpv3 api pipe".

Source: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv

@measured `curl -sS -f https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv | grep ',7431,'` 2026-10-22

## UDP and TCP ports 7432-7436

Result: Unassigned, listed as one registry row.

@measured `curl -sS -f https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv | grep ',7432-7436,'` 2026-10-22

Registry page date:

@measured `curl -sSL https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml | tr -d '\n' | sed -E 's/<[^>]+>/ /g' | tr -s ' ' | grep -o 'Last Updated [0-9-]*' | head -1` 2026-10-22 (prints `Last Updated 2026-10-20`)

## IPv6 multicast group ff02::114

Result: the registry row for this address reads "any private experiment".

Source: https://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xhtml

@measured `curl -sSL https://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xhtml | grep -n -A1 'FF0X:0:0:0:0:0:0:114'` 2026-10-22 (prints the `FF0X:0:0:0:0:0:0:114` row and, on the next line, `any private experiment`)

`@claude` 2026-10-22: reading of the registry notation. The `FF0X` row covers every scope, so ff02::114 (scope 2) is an instance of it.

@measured `curl -sSL https://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xhtml | grep -c 'FF02:0:0:0:0:0:0:114'` 2026-10-22 (prints 0: the registry has no separate row for ff02::114)

`@claude` 2026-10-22: reading of "any private experiment" as free for private use. rollcall does not reserve the group against other private software on the LAN.

Registry page date:

@measured `curl -sSL https://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xhtml | tr -d '\n' | sed -E 's/<[^>]+>/ /g' | tr -s ' ' | grep -o 'Last Updated [0-9-]*' | head -1` 2026-10-22 (prints `Last Updated 2026-04-07`)
