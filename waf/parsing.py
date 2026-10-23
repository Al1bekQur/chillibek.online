"""Parse request fields before inspection; never record their values."""
import json
from email import policy
from email.parser import BytesParser
from urllib.parse import parse_qsl


class InvalidInspectionInput(ValueError):
    pass


def request_values(path, query, content_type, body):
    values = [path]
    values.extend(part for pair in parse_qsl(query, keep_blank_values=True, max_num_fields=256) for part in pair)
    if not body:
        return values
    if 'json' in content_type.lower():
        try:
            parsed = json.loads(body)
        except (ValueError, RecursionError, UnicodeError) as error:
            raise InvalidInspectionInput('Invalid JSON body.') from error

        def visit(value, depth=0):
            if depth > 24 or len(values) > 2048:
                raise InvalidInspectionInput('JSON structure too complex.')
            if isinstance(value, dict):
                for key, item in value.items():
                    values.append(key)
                    visit(item, depth + 1)
            elif isinstance(value, list):
                for item in value:
                    visit(item, depth + 1)
            elif isinstance(value, str):
                values.append(value)
        visit(parsed)
    elif 'application/x-www-form-urlencoded' in content_type.lower():
        values.extend(part for pair in parse_qsl(body.decode('utf-8', 'strict'), keep_blank_values=True, max_num_fields=256) for part in pair)
    elif 'multipart/form-data' in content_type.lower():
        message = BytesParser(policy=policy.default).parsebytes(b'Content-Type: ' + content_type.encode('ascii') + b'\r\n\r\n' + body)
        if not message.is_multipart() or message.defects:
            raise InvalidInspectionInput('Malformed multipart body.')
        for index, part in enumerate(message.walk()):
            if index > 128:
                raise InvalidInspectionInput('Too many multipart parts.')
            if part.is_multipart():
                continue
            values.append(part.get_filename() or '')
            values.append((part.get_payload(decode=True) or b'').decode('utf-8', 'replace'))
    else:
        values.append(body.decode('utf-8', 'replace'))
    return values
