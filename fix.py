import sys

def main():
    content = ""
    with open("port/crates/rat-core/src/lib.rs", "r") as f:
        content = f.read()

    lines = content.split('\n')

    new_lines = []
    skip = False
    for i, line in enumerate(lines):
        if "if let (Ok(r_ip), Ok(c_ip)) = (remote_address.parse::<std::net::IpAddr>(), c.address.parse::<std::net::IpAddr>()) {" in line:
            new_lines.append(line)
        elif "if let Some(remote_address) = &self.remote_address {" in line:
            new_lines.append(line)
        elif "if *remote_address != c.address {" in line:
            pass # We accidentally left this in the output? Wait, no, I replaced it.
        else:
            new_lines.append(line)

if __name__ == "__main__":
    main()
