import json
import seahub_settings

db_infos = seahub_settings.DATABASES['default']

print(json.dumps(db_infos))
