#!/usr/bin/env python3
"""Export the current source's HTTP contract, or maintain its Collection projection."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
COLLECTION = 'crates/management-http/schema/Collection.json'


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
        if 'x-rss-directory-model' in value:
            marker=value['x-rss-directory-model']
            if not isinstance(marker,dict) or not marker.get('identity') or 'schema' not in marker:
                raise ValueError('invalid directory model marker')
            references(marker['schema'],root)
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
    owners, statistics = {}, []
    def directory(value):
        if value is None:
            return
        if value.get('kind') in ('window','body_window'):
            fixed=value.get('schema',{})
            if fixed.get('purpose') not in ('history','snapshot','qualification','references') or not fixed.get('reason','').strip():
                raise ValueError('fixed collection requires an explicit classification and reason')
            return
        if value.get('kind') != 'directory':
            return
        owner = value.get('schema', {})
        fields = owner.get('fields')
        if not owner.get('id') or not isinstance(fields, list) or not fields:
            raise ValueError('missing directory field owner')
        if owner.get('role') not in ('list','statistics') or not owner.get('modelIdentity'):
            raise ValueError('directory requires public model identity and role')
        description(owner.get('model'),'response')
        names = set()
        for field in fields:
            name, operators = field.get('name'), field.get('operators')
            if not isinstance(name, str) or not name or name in names:
                raise ValueError('duplicate or invalid directory field')
            names.add(name)
            if any(type(field.get(flag)) is not bool for flag in ('filter', 'sort', 'output', 'nullable')):
                raise ValueError('invalid directory capability flags')
            if not isinstance(operators, list) or any(not isinstance(op, str) for op in operators) or len(set(operators)) != len(operators):
                raise ValueError('invalid directory operator description')
            if bool(operators) != field['filter']:
                raise ValueError('directory operators differ from executable capability')
            if not field['filter'] and not field.get('limitation'):
                raise ValueError('directory exclusion requires a reason')
        if not set(owner.get('keys', [])) <= names:
            raise ValueError('unbound directory ordering key')
        selectors=owner.get('selectors')
        if not isinstance(selectors,list) or any(not isinstance(name,str) or name not in names for name in selectors) or len(set(selectors))!=len(selectors):
            raise ValueError('invalid typed domain selectors')
        contract={k:v for k,v in owner.items() if k!='role'}
        if owner['role']=='statistics':
            statistics.append(contract)
        elif owner['id'] in owners and owners[owner['id']]!=contract:
            raise ValueError('directory has conflicting model/execution owners')
        else:
            owners[owner['id']]=contract
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
        authentication = endpoint.get('authentication')
        if authentication is not None:
            if not isinstance(authentication, dict) or not authentication.get('owner') or not authentication.get('alternatives'):
                raise ValueError('missing authentication owner or credential alternatives')
            for credential in authentication['alternatives']:
                if not credential.get('owner') or not credential.get('kind'):
                    raise ValueError('missing credential owner')
                for schema in credential['headers'].values():
                    description(schema, 'request')
                if not set(credential['required_headers']) <= credential['headers'].keys():
                    raise ValueError('unbound credential header')
        request = endpoint.get('request')
        responses = endpoint.get('responses')
        if not isinstance(request, dict) or not isinstance(responses, list) or not responses:
            raise ValueError('missing endpoint request or responses')
        for key in ('path', 'query'):
            if request.get(key) is not None:
                description(request[key], 'request')
        directory(request.get('query_owner'))
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
    if any(owners.get(owner['id'])!=owner for owner in statistics):
        raise ValueError('statistics differs from its list model/execution owner')
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
        'FieldReferenceQuery': carrier('GET', '/api/v1/asset-fields/{field}/references', 'query'),
        'FieldReferences': carrier('GET', '/api/v1/asset-fields/{field}/references', 'response'),
        'ResourceReferences': carrier('GET', '/api/v1/resources/{id}/versions/{version}/references', 'response'),
        'GroupReferences': carrier('GET', '/api/v1/groups/{id}/references', 'response'),
        'PolicyWrite': carrier('POST', '/api/v1/policies/{policy}', 'request'),
        'PolicyView': carrier('GET', '/api/v1/policies/{policy}', 'response'),
        'PolicyScopeRead': carrier('GET', '/api/v1/policies/{policy}/scope', 'response'),
        'PolicyScopePreview': carrier('POST', '/api/v1/policies/{policy}/scope/previews', 'request'),
        'PolicyScopePreviewResult': carrier('POST', '/api/v1/policies/{policy}/scope/previews', 'response'),
        'PolicyScopeRecompute': carrier('POST', '/api/v1/policies/{policy}/scope/recomputations', 'request'),
        'PolicyScopeReceipt': carrier('POST', '/api/v1/policies/{policy}/scope/recomputations', 'response'),
        'GroupImpacts': carrier('GET', '/api/v1/groups/{id}/impacts', 'response'),
    }


def generated():
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
    document = validate_document(generated())
    content = (json.dumps(collection_projection(document), indent=2,
                          ensure_ascii=False, sort_keys=True) + '\n').encode()
    path = ROOT / COLLECTION
    if write:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    elif path.read_bytes() != content:
        raise ValueError(COLLECTION + ': differs from actual registered handlers; regenerate it')


def export(output):
    data = generated()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(data)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--write', action='store_true', help='regenerate only Collection.json')
    action.add_argument('--check', action='store_true', help='check only Collection.json drift')
    action.add_argument('--output', type=Path, help='export the full HTTP contract to this file')
    args = parser.parse_args(argv)
    try:
        if args.output is not None:
            export(args.output)
        else:
            check(args.write)
    except (ValueError, TypeError, AttributeError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print(f'HTTP contract: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
