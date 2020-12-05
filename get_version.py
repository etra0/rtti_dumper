import json
from subprocess import check_output

manifest = json.loads(check_output(["cargo", "read-manifest"]))

print("v" + manifest['version'])
