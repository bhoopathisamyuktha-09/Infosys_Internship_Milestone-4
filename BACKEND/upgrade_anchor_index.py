"""Upgrade anchor_event_id index to UNIQUE."""
import sys
sys.path.insert(0, '.')
from database.mongo_db import mongo
from pymongo import ASCENDING

mongo.connect()
db = mongo.get_database()
coll = db['incidents']

# Drop old non-unique anchor index
try:
    coll.drop_index('anchor_event_id_1')
    print('Dropped old non-unique anchor_event_id_1 index')
except Exception as e:
    print(f'Drop failed (may not exist): {e}')

# Create unique index
coll.create_index([('anchor_event_id', ASCENDING)], name='anchor_event_id_1', unique=True)
print('Created UNIQUE anchor_event_id_1 index')

# Verify
idx = coll.index_information()
ai = idx.get('anchor_event_id_1', {})
print('anchor_event_id_1 unique=%s' % ai.get('unique', False))
print('DONE')
