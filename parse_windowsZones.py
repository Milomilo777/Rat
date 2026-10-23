import xml.etree.ElementTree as ET
tree = ET.parse('windowsZones.xml')
root = tree.getroot()
print("pub fn map_windows_zone_to_iana(tz: &str) -> Option<&'static str> {")
print("    match tz {")
zones = {}
for mapZone in root.findall('.//mapZone'):
    territory = mapZone.get('territory')
    if territory == '001':
        other = mapZone.get('other')
        type_ = mapZone.get('type')
        # Handle cases where multiple types are specified
        iana = type_.split(' ')[0]
        zones[other] = iana

for other, iana in zones.items():
    print(f'        "{other}" => Some("{iana}"),')

print("        _ => None,")
print("    }")
print("}")
