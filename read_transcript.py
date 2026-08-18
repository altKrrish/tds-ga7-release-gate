import json
import os
import sys

sys.stdout.reconfigure(encoding='utf-8')

p = os.path.join(
    r'C:\Users\maste\.gemini\antigravity-ide\brain\d4b5950e-2910-486a-94f7-778b60d92b0f',
    '.system_generated', 'logs', 'transcript_full.jsonl'
)
lines = open(p, encoding='utf-8').readlines()
ui = [json.loads(l) for l in lines if '"USER_INPUT"' in l]
content = ui[-1].get('content', '')
# Find all download links
import re
urls = re.findall(r'https?://[^\s\r\n<>"\']+', content)
for u in urls:
    print(u)
