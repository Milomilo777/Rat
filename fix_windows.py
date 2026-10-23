with open('port/crates/rat-geo/src/lib.rs', 'r') as f:
    lines = f.readlines()

new_lines = []
skip_next = False
for line in lines:
    if skip_next:
        skip_next = False
        continue
    if 'Self::lookup_in_zone_tab(iana, "/usr/share/zoneinfo/zone.tab")' in line:
        new_lines.append(line)
        skip_next = True # skip None line
    else:
        new_lines.append(line)

with open('port/crates/rat-geo/src/lib.rs', 'w') as f:
    f.writelines(new_lines)
