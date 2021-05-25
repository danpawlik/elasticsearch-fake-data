#!/usr/bin/env python3

from elasticsearch import helpers


import argparse
import datetime
import elasticsearch
import json
import random
import uuid

json_sample = '''{
    "zuul_executor": "RANDOM_STRING",
    "message": " LOOP [load-logs : RANDOM_TEXT]",
    "voting": 1,
    "@version": "1",
    "build_short_uuid": "RANDOM_STRING",
    "timestamp": "2021-05-25 09:47:21.797",
    "build_status": "RANDOM_CHOICE",
    "tags": ["job-output.txt", "console", "console.html"],
    "project": "RANDOM_STRING",
    "build_queue": "check",
    "port": "RANDOM_NUMBER",
    "log_url": "https://RANDOM_STRING/logs/62/RANDOM_NUMBER/2/check/sf-tenants/RANDOM_STRING/job-output.txt",
    "build_branch": "master",
    "sep": "|",
    "filename": "job-output.txt",
    "build_ref": "refs/changes/62/RANDOM_NUMBER/2",
    "build_node": "cloud-centos-7",
    "build_uuid": "RANDOM_STRING",
    "host": "RANDOM_STRING",
    "build_name": "RANDOM_STRING",
    "build_change": "RANDOM_NUMBER",
    "build_master": "RANDOM_STRING",
    "build_zuul_url": "N/A",
    "@timestamp": "RANDOM_DATE",
    "type": "zuul",
    "build_patchset": "RANDOM_NUMBER",
    "node_provider": "vexxhost-nodepool-sf",
    "ms": "RANDOM_NUMBER"
}'''


def get_arguments():
    args_parser = argparse.ArgumentParser(
        description='Tool for generating fake data and push to ES')
    args_parser.add_argument('--host',
                             default='https://127.0.0.1:9200',
                             help='Elasticsearch http url')
    args_parser.add_argument('--index', help='Fake index name',
                             default='fake_index')
    args_parser.add_argument('--user', help='Username for auth to ES')
    args_parser.add_argument('--password', help='Password for auth to ES')
    args_parser.add_argument('--insecure', help='Skip SSL CA cert validation',
                             action="store_false")
    args_parser.add_argument('--count', default=100,
                             help='How many data should be generated')
    args_parser.add_argument('--debug', help='Print debug messages',
                             action='store_true')
    return args_parser.parse_args()


def get_rand_date():
    return datetime.date(random.randint(2005, 2145), random.randint(1, 12),
                         random.randint(1, 28)
                         ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def gen_rand_str(text):
    new_txt = ''
    if 'RANDOM_STRING' in text:
        new_txt = text.replace('RANDOM_STRING', uuid.uuid4().hex.upper())
    elif 'RANDOM_TEXT' in text:
        new_txt = text.replace('RANDOM_TEXT', ("%s %s %s" % (
            uuid.uuid4().hex.upper(),
            uuid.uuid4().hex.upper(),
            uuid.uuid4().hex.upper()))
        )
    elif 'RANDOM_CHOICE' in text:
        new_txt = text.replace('RANDOM_CHOICE', random.choice(
            ['SUCCESS', 'FAILURE', 'ERROR'])
        )
    elif 'RANDOM_DATE' in text:
        new_txt = text.replace('RANDOM_DATE', get_rand_date())
    elif 'RANDOM_NUMBER' in text:
        new_txt = text.replace('RANDOM_NUMBER', str(random.randint(1, 10000)))

    return new_txt if new_txt else text


def replace_data(text):
    new_txt = ""
    for word in text.split(' '):
        new_txt = text.replace(word, gen_rand_str(text))

    return new_txt


def gen_fake_data(text, debug):
    text = json.loads(text)
    for key, value in text.items():
        text[key] = replace_data(str(value))
    if debug:
        print(text)
    return text


def send_fake_data(host, user, password, count, debug, insecure, index):
    kwargs = {}
    if user and password:
        kwargs['http_auth'] = "%s:%s" % (user, password)

    kwargs['verify_certs'] = insecure
    if not insecure:
        kwargs['ssl_show_warn'] = insecure

    es = elasticsearch.Elasticsearch(host, **kwargs)

    try:
        es.info()
    except Exception as e:
        raise(e)

    for number in range(1, int(count)):
        generated_data = [gen_fake_data(json_sample, debug)]
        helpers.bulk(es, generated_data, index=index, doc_type="_doc")


if __name__ == '__main__':
    args = get_arguments()
    send_fake_data(args.host, args.user, args.password, args.count, args.debug,
                   args.insecure, args.index)
