import sys
import json

diff_json_file = open(sys.argv[1], 'r')
diff_data = json.load(diff_json_file)

output = []

for o in diff_data:
    # CVSSスコアが8以上の脆弱性がある場合は通知する
    for v in diff_data[o]:
        if v['cvss'] == None:
            continue
        for s in v['cvss']:
            if s['score'] >= 8.0:
                output.append({'fileName': o, 'vulnerabilityName': v['vulnerabilityName'], 'cvss': s})    
                break

if len(output) > 0:
    print('CVSSのスコアが8以上の脆弱性が見つかりました')
    for o in output:
        print('  - ファイル: {}, 脆弱性: {}, CVSS: ({}) {}'.format(o['fileName'], o['vulnerabilityName'], o['cvss']['version'], o['cvss']['score']))