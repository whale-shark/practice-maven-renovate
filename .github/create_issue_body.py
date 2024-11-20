import sys
import json

# 今回の脆弱性の結果から、Issueの本文を作成する
# owasp_json_file = open(sys.argv[1], 'r')
owasp_json_file = open('dependency-check-report.json', 'r')
owasp_data = json.load(owasp_json_file)

output = {}

def getCvssScore(vulnerability):
    # CVSSスコアを取得する
    rtn = []
    if 'cvssv2' in vulnerability:
        rtn.append({'version': 'v2', 'score': vulnerability['cvssv2']['score']})
    if 'cvssv3' in vulnerability:
        rtn.append({'version': 'v3', 'score': vulnerability['cvssv3']['baseScore']})
    if len(rtn) == 0:
        return None
    else:
        return rtn

def appendOutput(dependency, vulnerability):
    ary = output[dependency['fileName']] if dependency['fileName'] in output else []
    ary.append({'vulnerabilityName': vulnerability['name'], 'cvss': getCvssScore(vulnerability)})
    output[dependency['fileName']] = ary

for dependency in owasp_data['dependencies']:
    if 'vulnerabilities' in dependency:
        for vulnerability in dependency['vulnerabilities']:
            appendOutput(dependency, vulnerability)

if len(output) == 0:
    print('# 発見された脆弱性')
    print('**脆弱性は見つかりませんでした**🎉🎉')
    print('<!-- ___GITHUB_ACTIONS_DATA__ []-->')
else:
    print('# 発見された脆弱性')
    print('| ファイル名 | 脆弱性名 | CVSSバージョン| CVSSスコア |')
    print('|:-----------|:-----------|:------------:|:------------:|')
    for fileName in output:
        for vulnerability in output[fileName]:
            if vulnerability['cvss'] == None:
                print('| {} | {} | | |'.format(fileName, vulnerability['vulnerabilityName']))
            else:
                for cvss in vulnerability['cvss']:
                    print('| {} | {} | {} | {} |'.format(fileName, vulnerability['vulnerabilityName'], cvss['version'], cvss['score']))
    print('<!-- ___GITHUB_ACTIONS_DATA__ {}-->'.format(json.dumps(output)))
