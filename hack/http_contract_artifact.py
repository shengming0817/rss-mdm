#!/usr/bin/env python3
"""Check the product HTTP projection, or extract its exact committed bytes without Cargo."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = 'contracts/http-v1.json'


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError(f'duplicate JSON member: {key}')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('non-finite JSON number')))


def validate_document(data):
    document = strict_json(data)
    if not isinstance(document, dict) or type(document.get('formatVersion')) is not int or document['formatVersion'] != 1:
        raise ValueError('expected HTTP contract format V1')
    endpoints = document.get('endpoints')
    if not isinstance(endpoints, list) or not endpoints:
        raise ValueError('HTTP contract has no mounted endpoints')
    if document.get('schemaDialect') != 'https://json-schema.org/draft/2020-12/schema':
        raise ValueError('unsupported HTTP schema dialect')
    schemas = document.get('schemas')
    if not isinstance(schemas, dict) or not schemas:
        raise ValueError('HTTP contract has no schema definitions')
    def resolve(root, reference):
        if not isinstance(reference, str) or not reference.startswith('#'):
            raise ValueError('HTTP schemas must contain only local references')
        current = root
        if reference == '#':
            return
        if not reference.startswith('#/'):
            raise ValueError('unsupported schema reference')
        for part in reference[2:].split('/'):
            part = part.replace('~1', '/').replace('~0', '~')
            if not isinstance(current, dict) or part not in current:
                raise ValueError('unresolved schema reference')
            current = current[part]
    def references(value, root):
        if not isinstance(value, (dict, bool)):
            raise ValueError('invalid schema node')
        if isinstance(value, bool):
            return
        if '$dynamicRef' in value:
            raise ValueError('dynamic schema references are unsupported')
        if '$ref' in value:
            resolve(root, value['$ref'])
        for key in ('$defs', 'properties', 'patternProperties', 'dependentSchemas'):
            for child in value.get(key, {}).values():
                references(child, root)
        for key in ('allOf', 'anyOf', 'oneOf', 'prefixItems'):
            for child in value.get(key, []):
                references(child, root)
        for key in ('items', 'contains', 'additionalProperties', 'unevaluatedProperties',
                    'propertyNames', 'not', 'if', 'then', 'else', 'unevaluatedItems'):
            if key in value:
                references(value[key], root)
    for identity, schema in schemas.items():
        if not re.fullmatch(r'sha256-[0-9a-f]{64}', identity):
            raise ValueError('invalid schema identity')
        references(schema, schema)
    def description(value, direction):
        if not isinstance(value, dict) or value.get('direction') != direction or value.get('schemaId') not in schemas:
            raise ValueError('unbound or wrongly directed schema description')
    def body(value, direction):
        if value is not None:
            if not isinstance(value, dict) or not isinstance(value.get('content_type'), str):
                raise ValueError('missing body content type')
            description(value.get('schema'), direction)
    identities, routes = set(), set()
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            raise ValueError('invalid endpoint')
        identity = endpoint.get('operationId')
        listener, method, path = (endpoint.get(k) for k in ('listener', 'method', 'path'))
        if not all(isinstance(v, str) and v for v in (identity, listener, method, path)) or not path.startswith('/'):
            raise ValueError('endpoint identity or mounted path missing')
        if identity in identities or (listener, method, path) in routes:
            raise ValueError('duplicate endpoint identity or mounted route')
        request = endpoint.get('request')
        responses = endpoint.get('responses')
        if not isinstance(request, dict) or not isinstance(responses, list) or not responses:
            raise ValueError('missing endpoint request or responses')
        for key in ('path', 'query'):
            if request.get(key) is not None:
                description(request[key], 'request')
        body(request.get('body'), 'request')
        for header in request.get('headers', {}).values():
            description(header, 'request')
        for response in responses:
            if not isinstance(response, dict) or type(response.get('status')) is not int or not 100 <= response['status'] <= 599:
                raise ValueError('invalid response status')
            body(response.get('body'), 'response')
            for header in response.get('headers', {}).values():
                description(header, 'response')
        identities.add(identity)
        routes.add((listener, method, path))
    return document


def collection_projection(document):
    """The existing independent Collection consumer gets views of real mounted carriers."""
    def carrier(method, path, source):
        matches = [e for e in document['endpoints']
                   if (e['listener'], e['method'], e['path']) == ('browser', method, path)]
        if len(matches) != 1:
            raise ValueError('Collection projection has no unique mounted owner')
        endpoint = matches[0]
        if source == 'query':
            value = endpoint['request']['query']
        elif source == 'request':
            value = endpoint['request']['body']['schema']
        else:
            responses = [r for r in endpoint['responses'] if r['status'] == 200 and r.get('body')
                         and r['body']['content_type'] == 'application/json']
            if len(responses) != 1:
                raise ValueError('Collection projection has no unique success body')
            value = responses[0]['body']['schema']
        return document['schemas'][value['schemaId']]
    def named(root, name):
        # Reuse definitions from the actual response, retaining only their reference closure.
        definitions = root.get('$defs', {})
        if name not in definitions:
            raise ValueError('Collection response owner no longer defines ' + name)
        selected = dict(definitions[name])
        needed, pending = {}, [selected]
        def refs(value):
            if isinstance(value, dict):
                if isinstance(value.get('$ref'), str):
                    yield value['$ref']
                for key, child in value.items():
                    if key not in ('const', 'enum', 'default', 'examples'):
                        yield from refs(child)
            elif isinstance(value, list):
                for child in value:
                    yield from refs(child)
        while pending:
            for reference in refs(pending.pop()):
                if not reference.startswith('#/$defs/'):
                    raise ValueError('unsupported Collection owner reference')
                key = reference[len('#/$defs/'):].replace('~1', '/').replace('~0', '~')
                if key not in definitions:
                    raise ValueError('unresolved Collection owner reference')
                if key not in needed:
                    needed[key] = definitions[key]
                    pending.append(definitions[key])
        selected.update({'$schema': document['schemaDialect'], 'title': name})
        if needed:
            selected['$defs'] = needed
        return selected
    field = carrier('GET', '/api/v1/asset-fields/{field}', 'response')
    return {
        'ResourceWrite': carrier('POST', '/api/v1/resources/{id}', 'request'),
        'ResourceResponse': carrier('POST', '/api/v1/resources/{id}', 'response'),
        'FieldWrite': carrier('PUT', '/api/v1/asset-fields/{field}', 'request'),
        'FieldView': named(field, 'FieldView'),
        'FieldImpact': named(field, 'FieldImpact'),
        'FieldReferenceQuery': carrier('GET', '/api/v1/asset-fields/{field}/references', 'query'),
        'FieldMappingReference': named(field, 'FieldMappingReference'),
    }


def generated():
    # Keep extraction usable with Python and Git alone. Build support belongs only to regeneration.
    from build_run import LEASE_ENV, lease_fds, require_lease
    cargo = ['cargo', 'run', '--quiet', '--locked', '-p', 'rss-mdm-app', '--example', 'http_contract']
    if LEASE_ENV in os.environ:
        require_lease(ROOT)
        command, fds = cargo, lease_fds()
    else:
        command, fds = [sys.executable, str(ROOT / 'hack/build_run.py'), '--', *cargo], ()
    data = subprocess.run(command, cwd=ROOT, pass_fds=fds, check=True, stdout=subprocess.PIPE).stdout
    validate_document(data)
    return data


def check(write=False):
    expected = generated()
    document = validate_document(expected)
    projections = {ARTIFACT: expected,
        'crates/management-http/schema/Collection.json':
            (json.dumps(collection_projection(document), indent=2, ensure_ascii=False, sort_keys=True) + '\n').encode()}
    for relative, content in projections.items():
        path = ROOT / relative
        if write:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        if path.read_bytes() != content:
            raise ValueError(relative + ': differs from actual registered handlers; regenerate it')


def git(repository, *arguments):
    return subprocess.run(['/usr/bin/git', '-C', str(repository), *arguments], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def committed(repository, revision):
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('an exact lowercase 40-character commit is required')
    actual = git(repository, 'rev-parse', '--verify', revision + '^{commit}').decode().strip()
    if actual != revision:
        raise ValueError('revision is not the requested commit object')
    blob = git(repository, 'rev-parse', '--verify', revision + ':' + ARTIFACT).decode().strip()
    if git(repository, 'cat-file', '-t', blob).strip() != b'blob':
        raise ValueError('HTTP artifact is not a Git blob')
    data = git(repository, 'cat-file', 'blob', blob)
    validate_document(data)
    return data, {'sourceRevision': actual, 'path': ARTIFACT, 'blob': blob,
                  'sha256': hashlib.sha256(data).hexdigest()}


def source_file(path):
    return path.with_name(path.name + '.source.json')


def extract(repository, revision, output):
    data, source = committed(repository, revision)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(data)
    source_file(output).write_text(json.dumps(source, indent=2) + '\n')


def verify_source(repository, revision, path):
    expected, source = committed(repository, revision)
    if path.read_bytes() != expected:
        raise ValueError('HTTP artifact differs from the selected Git object')
    if strict_json(source_file(path).read_bytes()) != source:
        raise ValueError('HTTP source receipt differs from the selected Git objects')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--write', action='store_true')
    action.add_argument('--check', action='store_true')
    action.add_argument('--extract', metavar='COMMIT')
    action.add_argument('--verify-source', metavar='COMMIT')
    parser.add_argument('--repository', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--input', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.extract:
            if args.output is None or args.input is not None:
                parser.error('--extract requires --output and rejects --input')
            extract(args.repository or ROOT, args.extract, args.output)
        elif args.verify_source:
            if args.input is None or args.output is not None:
                parser.error('--verify-source requires --input and rejects --output')
            verify_source(args.repository or ROOT, args.verify_source, args.input)
        else:
            if any(v is not None for v in (args.repository, args.input, args.output)):
                parser.error('source/output options apply only to fixed-commit operations')
            check(args.write)
    except (ValueError, TypeError, AttributeError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print(f'HTTP contract: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
