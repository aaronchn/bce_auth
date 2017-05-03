#!/usr/bin/env python
# -*- coding: utf-8 -*-
# I'm very disappointed about BCE’s HOW—TO documents and customer service

import urllib
import hmac, hashlib
from datetime import datetime

def digest(key, msg):
    """消息摘要算法（加盐）"""
    digester = hmac.new(key, msg, hashlib.sha256)
    HMAC_SHA256 = digester.hexdigest()
    return HMAC_SHA256

def querystring_be_canonical(string):
    """
    test case
    string = 'text&text1=测试&text10=test'
    string = ''
    """
    if string != '':
        lst = string.split('&')
        string_lst = []
        for i in lst:

            if '=' in i:
                string_lst.append( urllib.quote(i, safe='='))
            else:
                string_lst.append( urllib.quote(i, safe='') + '=')

        string_lst.sort()
        qs_canonical = '&'.join(string_lst)
    else:
        qs_canonical = ''

    return qs_canonical

def headers_be_canonical(headers):
    keys = []
    items = []

    for k, v in headers.items():
        keys.append(k.lower())

        item = "{}:{}".format(urllib.quote(k.lower(), safe=''), urllib.quote(v.strip(), safe=''))
        items.append(item)

    #"注意相关举例2： CanonicalHeaders的排序和signedHeaders排序不一致。"
    keys.sort()
    keys = ';'.join(keys)

    items.sort()
    headers_plain = '\n'.join(items)

    return keys, headers_plain

def get_headers_with_auth(conf, payload, querystring):

    contentLength = str(len(payload))
    time_bce = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

    #自行评估哪些header会出现在提交的请求内，继而在此对这些headers进行声明
    req_headers = {'Host': conf['host'],
                   'Content-Type' : conf['contentType'],
                   'Content-Length' : contentLength,
                   'x-bce-date' : time_bce
                   }

    #获取已编码并扁平化的Headers字串
    headers_signed, headers_canonical = headers_be_canonical(req_headers)

    #对请求的资源路径编码
    uri_canonical = urllib.quote (conf['path'], safe='/')

    #对请求携带的查询参数编码
    querystring_canonical = querystring_be_canonical(querystring)

    #构造合规化请求字串
    request_canonical = '\n'.join([conf['method'].upper(), uri_canonical, querystring_canonical, headers_canonical])

    #认证字串前缀
    authStringPrefix = conf['auth_version'] + '/' + conf['ak'] + '/'  + time_bce + '/'  + '1800'

    #摘要算法需用到的key
    signing_key = digest(conf['sk'], authStringPrefix)

    #摘要
    signature = digest(signing_key, request_canonical)

    #构造认证字串(显式声明已参与签名的所有header，而非采用由百度定义的缺省方式)
    authorization =  authStringPrefix + '/' + headers_signed + '/' + signature

    #为原始请求headers附加认证字串header
    req_headers['Authorization'] = authorization

    return req_headers

if __name__ == '__main__':
    conf = {'ak':'',
            'sk':'',
            'host':'sms.bj.baidubce.com',
            'protocol':'http',
            'method':'post',
            'path':'/bce/v2/message',
            'auth_version':'bce-auth-v1',
            'contentType':'application/json'
            }

    template_x={"invokeId": '',
                "phoneNumber": '',
                "templateCode": 'smsTpl:e7476122a1c24e37b3b0de19d04ae902',
                "contentVar": {"code": '666',
                               "hour": '8',
                               }
                }
    import json
    payload = json.dumps(template_x)
    querystring = ''
    print get_headers_with_auth(conf, payload, querystring)

