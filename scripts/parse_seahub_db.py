import json
import seahub_settings

db_infos = seahub_settings.DATABASES['default']

with open('/tmp/seahub_db.json', 'w') as f:
    json.dump(db_infos, f, indent=4)

