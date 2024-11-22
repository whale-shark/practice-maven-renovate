import sys
import json

# 以前の脆弱性の結果と今回の脆弱性の結果を比較して、新たに登録された脆弱性を取得する
issue_json_file = open(sys.argv[1], 'r')
owasp_json_file = open(sys.argv[2], 'r')
issue_data = json.load(issue_json_file)
owasp_data = json.load(owasp_json_file)

output = {} # key: fileName, value: [{updateType: 'new or update', vulnerabilityName: 'vulnerabilityName', cvss: [{version: 'v2', score: 8.0}]}]

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

def appendOutput(dependency, vulnerability, updateType):
    ary = output[dependency['fileName']] if dependency['fileName'] in output else []
    ary.append({'updateType': updateType, 'vulnerabilityName': vulnerability['name'], 'cvss': getCvssScore(vulnerability)})
    output[dependency['fileName']] = ary

for dependency in owasp_data['dependencies']:
    if 'vulnerabilities' in dependency:
        # 脆弱性単位で登録されているかチェック
        for vulnerability in dependency['vulnerabilities']:
            # issue_dataのfileNameと一致するデータがあるかチェック
            issue_key = next((x for x in issue_data if x == dependency['fileName']), None)
            if issue_key != None:
                issue = issue_data[issue_key]
                issue_vulnerability = next ((x for x in issue if x['vulnerabilityName'] == vulnerability['name']), None)
                # データがある場合は、脆弱性の名前やCVE番号が一致しているかチェック
                if issue_vulnerability == None:
                    appendOutput(dependency, vulnerability, 'new')
                # 名前は一致しているがCVE番号が異なる場合は、新たに登録された脆弱性として扱う
                else:
                    if getCvssScore(vulnerability) != issue_vulnerability['cvss']:
                        appendOutput(dependency, vulnerability, 'update')
            else:
                # データがないので新規の脆弱性
                appendOutput(dependency, vulnerability, 'new')

save_file = open(sys.argv[3], 'w')
json.dump(output, save_file, indent=4)