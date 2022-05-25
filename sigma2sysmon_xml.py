import xml.etree.ElementTree as ET
from xml.etree import cElementTree as cET
from fnmatch import fnmatch
from itertools import product
from os import path as os_path, walk as os_walk
from yaml import safe_load
from json import dump as json_dump
from xml.dom import minidom
from uuid import uuid1
from copy import copy

# SIGMA HQ YAML rule to sysmon xml rule converter

# ref:
# https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml
# https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
# https://posts.specterops.io/putting-sysmon-v9-0-and-or-grouping-logic-to-the-test-c3ec27263df8
# https://github.com/nshalabi/SysmonTools
# https://techcommunity.microsoft.com/t5/sysinternals-blog/sysmon-the-rules-about-rules/ba-p/733649
# https://medium.com/@browninfosecguy/sysmon-101-7bf99e22fb0c

# input:
#   Sigma HQ yaml rule file(s)
# output:
#   sysmon_rule.xml
#   sigma_hq_rule_id_to_rule_meta_mapping.json

# 输出映射表：
# id -> 规则全部内容，除了id、logsource、detection

# 输出SYSMON规则XML：
# 每一个SIGMA HQ规则是XML中的一个RuleGroup（规则组），RuleGroup的name属性是规则的id
# 这样当规则被触发的时候，数据的RuleName字段会带上触发的规则id，在数据端通过id查找对应的规则信息即可
# 规则组内利用SYSMON规则的逻辑构造等价逻辑规则

sysmonEventFieldMapping = { # 字段名映射
    "1": {
        'EventID': None,
        'Commandline': 'CommandLine',
        'OriginalFilename': 'OriginalFileName',
        'OriginalName': 'OriginalFileName',
        'ParentUser': None
    },
    "2": {
        'EventID': None
    },
    "3": {
        'TargetPort': 'DestinationPort',
        'EventID': None
    },
    "5": {
        'EventID': None
    },
    "6": {
        'EventID': None
    },
    "7": {
        'EventID': None
    },
    "8": {
        'EventID': None
    },
    "9": {
        'EventID': None
    },
    "10": {
        'EventID': None
    },
    "11": {
        'FileName': "TargetFilename",
        'User': None
    },
    "12": {
        'EventID': None,
        'User': None
    },
    "13": {
        'EventID': None,
        'User': None
    },
    "14": {
        'EventID': None,
        'User': None
    },
    "15": {
        'EventID': None
    },
    "17": {
        'EventID': None
    },
    "18": {
        'EventID': None
    },
    "19": {
        'EventID': None
    },
    "20": {
        'EventID': None
    },
    "21": {
        'EventID': None
    },
    "22": {
        'EventID': None
    },
    "23": {
        'EventID': None
    },
    "24": {
        'EventID': None
    },
    "25": {
        'EventID': None
    },
    "26": {
        'EventID': None
    }
}

sysmonEventIdMapping = {
    '1':'ProcessCreate',
    '2':'FileCreateTime',
    '3':'NetworkConnect',
    '5':'ProcessTerminate',
    '6':'DriverLoad',
    '7':'ImageLoad',
    '8':'CreateRemoteThread',
    '9':'RawAccessRead',
    '10':'ProcessAccess',
    '11':'FileCreate',
    '12':'RegistryEvent',
    '13':'RegistryEvent',
    '14':'RegistryEvent',
    '15':'FileCreateStreamHash',
    '17':'PipeEvent',
    '18':'PipeEvent',
    '19':'WmiEvent',
    '20':'WmiEvent',
    '21':'WmiEvent',
    '22':'DnsQuery',
    '23':'FileDelete',
    '24':'ClipboardChange',
    '25':'ProcessTampering',
    # '26':'FileDeleteDetected',
}

catalogMapping = {# logsource.catalog -> sysmon eventid
    "create_remote_thread"      : "8",
    "create_stream_hash"        : "15",
    "dns_query"                 : "22",
    "driver_load"               : "6",
    "file_access"               : "11",
    "file_delete"               : "23",
    "file_event"                : "11",
    "image_load"                : "7",
    "network_connection"        : "3",
    "pipe_created"              : "17",
    "process_access"            : "10",
    "process_creation"          : "1",
    "process_tampering"         : "25",
    "raw_access_thread"         : "9",
    "registry_add"              : "12",
    "registry_delete"           : "12",
    "registry_event"            : "14",
    "registry_set"              : "13",
    "wmi_event"                 : "20"
}

modifierMapping = { # sigma hq字段匹配条件转sysmon条件，在匹配字段名后再加一个|，
    'endswith'                  : 'end with',
    'startswith'                : 'begin with',
    'contains'                  : 'contains',
    'contains|all'              : 'contains all',
    ''                          : 'is'
}

reverseMapping = { # sysmon字段匹配条件取反映射
    'is'                        : 'is not',
    'contains'                  : 'excludes',
    'contains all'              : 'excludes any',
    'contains any'              : 'excludes all',
    'begin with'                : 'not begin with',
    'end with'                  : 'not end with',
    'less than'                 : 'more than',
    'is not'                    : 'is',
    'excludes'                  : 'contains',
    'excludes any'              : 'contains all',
    'excludes all'              : 'contains any',
    'not begin with'            : 'begin with',
    'not end with'              : 'end with',
    'more than'                 : 'less than'
}
# 挑战：SigmaHQ规则规范化
# 现状：SigmaHQ规则的detection中，除了condition以外，每个条件组内的条件都是and关系，组之间的关系由condition定义
# 目标：将SigmaHQ的规则逻辑转化成SYSMON XML规则
# 难点：SYSMON XML规则支持以规则组的形式构建过滤规则，当数据匹配规则组的时候，记录中RuleName字段会带上命中的规则组的name属性。
#       sysmon xml的规则组内分为include组和exclude两个组：分别是命中匹配和失配匹配。
#       但由于XML规则组之间一般是or关系，规则组内字段/条件不同的规则条目之间是AND关系，字段和条件都相同的条目之间是OR关系。
#       需要将SIGMA HQ规则的condition进行规范化，使之在规则逻辑层能够转化成SYSMON XML规则
#       并将规则的ID作为规则组的名称，这样当数据命中对应的规则组时，可以从RuleName字段得知命中的是哪个规则
# 实现：
# sysmon xml规则组之间的关系通过groupRelation属性指定，但一般情况下都用or关系。因为AND关系会导致冲突（无法同时指定include/exclude）
# sysmon XML规则的规则组内，相同字段相同条件，例如都是<Image condition="end with" />，规则条目之间的关系是or。字段和条件只要有一个不相同，关系就是and。
# sigma hq规则的条件组内，如果是字典类型，则是AND关系，如果是列表类型，则是OR关系。一般都用AND。
# 需要将condition规范化：去掉所有括号，改写成由or关系连接的一个个仅用and和not构成的逻辑。
# 而且由于not和or逻辑的分配律，将sigma hq的条件组全部转化成include会将逻辑变得极为复杂（not (a and b) = not a or not b），因此需要将not逻辑的条件组放入exclude
# 由于sysmon xml规则的逻辑限制，转化时必须将condition规范化成若干or关系连接的仅由and和not逻辑构成的逻辑。运算优先级 not > and > or
# or逻辑连接的子逻辑通过构建多个之间逻辑关系为or且RuleGroup name (id)相同的规则组实现
#   and逻辑：放入include组
#   not逻辑：放入exclude组
#   or关系：按or关系为分界，拆分成若干只包含and和not的组，分别生成or关系的规则组。
#   not 1 of * : 不得匹配*中任意一个组->*中所有组的关系是or，最后取反 not (a or b) = not a and not b->*中每个组的匹配条件取反之后放入include
#   1 of *：匹配*中任意一个组->*中所有组的关系是or->对应和and规则排列组合一下
#   all of *：匹配*中所有组->*中所有组的关系是and->直接融合？
# 在逻辑问题之外，xml还需要按特定的顺序写入文件，否则会触发类似这样的错误：
# Element RuleGroup content does not follow the DTD, expecting (ProcessCreate | FileCreateTime | NetworkConnect | ProcessTerminate | DriverLoad | ImageLoad | CreateRemoteThread | RawAccessRead | ProcessAccess | FileCreate | RegistryEvent | FileCreateStreamHash | PipeEvent | WmiEvent | DnsQuery | FileDelete | ClipboardChange | ProcessTampering)*, got (DNSQuery DNSQuery )
# 包括事件和规则内容都需要遵守这个顺序。

def dictify(r,root=True):
    if root:
        return {r.tag : dictify(r, False)}
    d=copy(r.attrib)
    if r.text:
        d["_text"]=r.text
    for x in r.findall("./*"):
        if x.tag not in d:
            d[x.tag]=[]
        d[x.tag].append(dictify(x,False))
    return d

def xml2dict(xmlFile, encoding='utf-8')->dict:
    return dictify(ET.parse(open(xmlFile, 'r', encoding=encoding)).getroot())

def detectionNormalizator(detection: dict, conditionText:str = '') -> list:
    '将输入的条件文本转化成仅使用and和not逻辑关系的若干条件组，每个条件组之间是or关系，条件组内部是and关系'
    # 后续还需要处理文本中的通配符*，包含*的字符串，*一律替换成;，并将条件改为contains all
    # 第一步：空格标准化，去掉两端的非打印字符，去掉所有' and '
    if 'timeframe' in detection:
        yield []
    else:
        conditionText = detection.pop('condition', conditionText).strip()
        if any(map(conditionText.__contains__, [' by '])) or not conditionText:
            yield []
        else:
            if conditionText[1] + conditionText[-1] == '()' and conditionText.count('(')+conditionText.count(')') == 2:
                conditionText = conditionText[1:-1]
            newConditionText = ''
            for i in range(0, len(conditionText)):
                newConditionText += conditionText[i] if conditionText[i].isprintable() else ' '
            while newConditionText.find('  ') != -1:
                newConditionText = newConditionText.replace('  ', ' ')
            newConditionText = newConditionText.replace(' and ',' ').replace('not ', '#not_').replace('1 of ', '#1_of_').replace('any of ', '#1_of_').replace('all of ', '#all_of_')
            orConditions = newConditionText.split(' or ')
            # 第二步：按or逻辑分段，每一段内部都是and。然后对每一段处理1 of的情况
            for subCondition in orConditions:
                tmpInclude = []
                tmpExclude = []
                for subConditionItem in subCondition.split(' '):
                    if subConditionItem.startswith("#not_#1_of_"): # not 1 of情况
                        for wildcardItem in filter(lambda x:fnmatch(x, subConditionItem[11:]), detection.keys()):
                            if not type(detection[wildcardItem]) == list:
                                detection[wildcardItem] = [detection[wildcardItem]]
                            for detectionOrItem in detection[wildcardItem]:
                                tmpExclude.append(
                                    dict(
                                        zip(
                                            map(
                                                lambda modifier: '#'.join([wildcardItem, modifier]),
                                                detectionOrItem.keys()
                                            ),
                                            detectionOrItem.values()
                                        )
                                    )
                                )
                    elif subConditionItem.startswith("#1_of_"): # 1 of 情况
                        for wildcardItem in filter(lambda x:fnmatch(x, subConditionItem[6:]), detection.keys()):
                            if type(detection[wildcardItem]) != list:
                                detection[wildcardItem] = [detection[wildcardItem]]
                            for detectionOrItem in detection[wildcardItem]:
                                tmpInclude.append(
                                    dict(
                                        zip(
                                            map(
                                                lambda modifier: '#'.join([wildcardItem, modifier]),
                                                detectionOrItem.keys()
                                            ),
                                            detectionOrItem.values()
                                        )
                                    )
                                )
                    elif subConditionItem.startswith("#all_of_"): # all of 情况
                        merge = {}
                        for wildcardItem in filter(lambda x:fnmatch(x, subConditionItem[8:]), detection.keys()):
                            if type(detection[wildcardItem]) != list:
                                detection[wildcardItem] = [detection[wildcardItem]]
                            # if type(detection[wildcardItem]) == dict:
                            #     merge.update(
                            #         dict(
                            #             zip(
                            #                 map(
                            #                     lambda modifier: '#'.join([wildcardItem, modifier]),
                            #                     detection[wildcardItem].keys()
                            #                 ),
                            #                 detection[wildcardItem].values()
                            #             )
                            #         )
                            #     )
                            #     tmpInclude.append(merge)
                            # if type(detection[wildcardItem]) == list:
                            for detectionOrItem in detection[wildcardItem]:
                                tmpInclude.append(
                                    {
                                        **merge,
                                        **dict(
                                            zip(
                                                map(
                                                    lambda modifier: '#'.join([wildcardItem, modifier]),
                                                    detectionOrItem.keys()
                                                ),
                                                detectionOrItem.values()
                                            )
                                        )
                                    }
                                )

                            # tmpInclude.append(
                            #     dict(
                            #         zip(
                            #             map(
                            #                 lambda modifier: '#'.join([wildcardItem, modifier]),
                            #                 detection[wildcardItem].keys()
                            #             ),
                            #             detection[wildcardItem].values()
                            #         )
                            #     )
                            # )

                    elif subConditionItem.startswith("#not_"): # not 情况
                        if type(detection[subConditionItem[5:]])!=list:
                            detection[subConditionItem[5:]] = [detection[subConditionItem[5:]]]
                        for detectionOrItem in detection[subConditionItem[5:]]:
                            tmpExclude.append(
                                dict(
                                    zip(
                                        map(
                                            lambda x:'%s#%s'%(subConditionItem, x),
                                            detectionOrItem.keys()
                                        ),
                                        detectionOrItem.values()
                                    )
                                )
                            )
                    else:
                        if type(detection[subConditionItem]) != list:
                            detection[subConditionItem] = [detection[subConditionItem]]
                        for detectionOrItem in detection[subConditionItem]:
                            tmpInclude.append( # 列表
                                dict(
                                    zip(
                                        map(
                                            lambda x:'%s#%s'%(detectionOrItem, x),
                                            detectionOrItem.keys()
                                        ),
                                        detectionOrItem.values()
                                    )
                                )
                            )
                        # else:
                        #     tmpInclude.append( # 正常
                        #         dict(
                        #             zip(
                        #                 map(
                        #                     lambda x:'%s#%s'%(subConditionItem, x),
                        #                     detection[subConditionItem].keys()
                        #                 ),
                        #                 detection[subConditionItem].values()
                        #             )
                        #         )
                        #     )
                for includeItems, excludeItems in product(
                    tmpInclude if tmpInclude else [{}],
                    tmpExclude if tmpExclude else [{}]
                ):
                    yield {
                        'include': includeItems,
                        'exclude': excludeItems
                    }

def walkDirForFile(rootDir):
    if not os_path.isdir(rootDir):
        yield
    for root, dirs, files in os_walk(rootDir):
        for file in files:
            yield os_path.join(root, file)
        for dir in dirs:
            walkDirForFile(os_path.join(root, dir))

def sigmaHqRule2XmlNode(ruleItem:dict, parentNode, fieldOrders:dict):
    # ruleItem = safe_load(open(sigmaYaml, 'r', encoding='utf-8'))
    if not ruleItem['logsource'].get('category') in catalogMapping:
        # print('not vaild sysmon rule: %s' % yamlFile)
        return None
    sysmonEvent = catalogMapping[ruleItem['logsource']['category']]
    ruleId = ruleItem['id']
    selections = detectionNormalizator(ruleItem.pop('detection', {}))
    if not selections:
        return None
    for selection in selections:
        ruleGroup = ET.SubElement(parentNode, 'RuleGroup', {'name': ruleId, 'groupRelation': 'or'})
        for condition in selection:
            subGroup = ET.SubElement(ruleGroup, sysmonEventIdMapping[sysmonEvent], {'onmatch': condition})
            fieldOrder = fieldOrders[sysmonEvent]
            fieldNameMapping = sysmonEventFieldMapping[sysmonEvent]
            fieldRules = {}
            for matching in selection[condition]:
                matchValue = selection[condition][matching]
                matching+='|'
                matching = matching[matching.rfind('#')+1:]
                fieldName, modifier = matching.split('|', 1)
                if fieldName in fieldNameMapping:
                    fieldName = fieldNameMapping[fieldName]
                if not fieldName: continue
                if not fieldName in fieldOrder:
                    print('invalid field name: %s for event %s.' % (fieldName, sysmonEvent))
                    return None
                if fieldName not in fieldRules: fieldRules[fieldName] = list()
                if modifier and modifier[-1] == '|': modifier = modifier[:-1]
                
                if modifier not in  modifierMapping:
                    print('unsupported modifier: %s' % modifier)
                    return None
                if type(matchValue) == str and '*' in matchValue:
                    matchValue = matchValue.replace('*', ';')
                    modifier = 'contains|all'
                fieldRules[fieldName].append(
                    {
                        'modifier': modifierMapping[modifier],
                        'pattern': matchValue
                    }
                )
            for fName in fieldOrder:
                for item in fieldRules.get(fName, []):
                    if type(item['pattern']) == list:
                        for matchItem in item['pattern']:
                            ET.SubElement(subGroup, fName, {'condition': item['modifier']}).text = str(matchItem)
                            # matchingNode = ET.SubElement(subGroup, fName, {'condition': item['modifier']}).text = str(matchItem)
                            # matchingNode.text = str(matchItem)
                    else:
                        ET.SubElement(
                            subGroup,
                            fName, 
                            {'condition': item['modifier']}
                        ).text = str(item['pattern']) if not item['pattern'] is None else ""
                        # matchingNode = ET.SubElement(subGroup, fName, {'condition': item['modifier']})
                        # matchingNode.text = str(item['pattern']) if not item['pattern'] is None else ""
    return ruleItem

def rcLoadSigmaRule(inputBaseDir:str, eventOrder:list)->dict:
    rtn={}
    for yamlFile in filter(lambda s:s.lower().endswith('.yml'), walkDirForFile(inputBaseDir)):
        ruleItem = safe_load(open(yamlFile, 'r', encoding='utf-8'))
        sysmonCatalog = catalogMapping.get(ruleItem.get('logsource', {}).get('category', None))
        if not sysmonCatalog or sysmonCatalog not in eventOrder:
            continue
        if sysmonCatalog not in rtn: rtn[sysmonCatalog] = list()
        rtn[sysmonCatalog].append(ruleItem)
    return rtn

schemaversion="4.50"
baseDir = r'D:\My Works\Honey_2022\sigma-master\rules\windows'
outputRuleXml = os_path.join(os_path.dirname(__file__), 'sigma_hq_sysmon.xml')
outputIdMappingJson = os_path.join(os_path.dirname(__file__), 'mapping.json')

if __name__ == '__main__':
    schemaXmlFile = os_path.join(os_path.dirname(__file__), 'schema.xml')
    # build ordered event list from schema.xml (sysmon.exe -s command output) on the fly
    schemaEventList = xml2dict(schemaXmlFile)['manifest']['events'][0]['event']
    eventOrder = {i['value']: i['rulename'] for i in schemaEventList if 'rulename' in i and 'value' in i}
    eventFieldMapping = {
        i['value']:[j['name'] for j in i['data']] for i in schemaEventList if 'value' in i
    }
    outputMapping = {}
    xmlRoot = ET.Element("Sysmon",{"schemaversion": schemaversion})
    eventFilterBody = ET.SubElement(xmlRoot,'EventFiltering')
    validRuleCounter = 0
    ruleItems = rcLoadSigmaRule(baseDir, eventOrder)

    for eventName in eventOrder:
        # ruleItem = 
        for ruleItem in ruleItems.get(eventName, []):
            sigmaHqRule2XmlNode(ruleItem, eventFilterBody, eventFieldMapping)
            if ruleItem:
                outputMapping[ruleItem['id'] if 'id' in ruleItem else str(uuid1())] = ruleItem
                # print(yamlFile)
                validRuleCounter+=1
    rawXml = ET.tostring(xmlRoot, encoding='utf-8').decode('utf-8')
    open(outputRuleXml, 'w', encoding='utf-8').write(minidom.parseString(rawXml).toprettyxml(indent="\t"))
    json_dump(outputMapping, open(outputIdMappingJson, 'w', encoding='utf-8'), indent=4, ensure_ascii=False)
    print(validRuleCounter)