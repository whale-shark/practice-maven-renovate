import sys
import json

diff_json_file = open(sys.argv[1], 'r')
diff_data = json.load(diff_json_file)

def getFormatScore(v):
    rtn = []
    if (v['cvss'] == None):
        return 'なし'
    for s in v['cvss']:
        rtn.append('({}) {}'.format(s['version'], s['score']))
    return ', '.join(rtn)

for o in diff_data:
    print('- 対象のファイル: {}'.format(o))
    for v in diff_data[o]:
        if v['updateType'] == 'new':
            print('  - 新たに発見された脆弱性: {}, スコア: {}'.format(v['vulnerabilityName'], getFormatScore(v)))
        else:
            print('  - 更新された脆弱性: {}, スコア: {}'.format(v['vulnerabilityName'], getFormatScore(v)))

