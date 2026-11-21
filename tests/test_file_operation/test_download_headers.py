import re
from urllib.parse import quote, unquote

import pytest
import requests

from seaserv import seafile_api as api
from tests.config import USER


@pytest.mark.parametrize('filename,expected_filename', [
    pytest.param('quoted"name.txt', 'quoted_name.txt', id='double-quote'),
    pytest.param('back\\slash.txt', 'back_slash.txt', id='backslash'),
    pytest.param('"quoted\\name".txt', '_quoted_name_.txt', id='mixed'),
    pytest.param('line\r\nbreak.txt', 'line__break.txt', id='crlf'),
    pytest.param('delete\x7fname.txt', 'delete_name.txt', id='del'),
    pytest.param("space ;,='().txt", "space ;,='().txt", id='allowed-qdtext'),
    pytest.param('\u4e2d\u6587.txt', 'download.txt', id='chinese'),
    pytest.param('caf\u00e9.PDF', 'download.PDF', id='non-ascii-latin'),
    pytest.param('\u4e2d\u6587.tar.gz', 'download.gz', id='multiple-extensions'),
    pytest.param('\u4e2d\u6587', 'download', id='no-extension'),
    pytest.param('\u4e2d\u6587.\u6587\u672c', 'download', id='non-ascii-extension'),
    pytest.param('\u4e2d\u6587.tx"t', 'download.tx_t', id='unsafe-ascii-extension'),
])
@pytest.mark.parametrize('byte_range', [False, True], ids=['full', 'range'])
def test_download_header_filename(repo, tmp_path, filename, expected_filename,
                                  byte_range):
    content = b'File content for download header testing.\n'
    source = tmp_path / 'source.txt'
    source.write_bytes(content)
    assert api.post_file(repo.id, str(source), '/', filename, USER) == 0
    file_id = api.get_file_id_by_path(repo.id, '/' + filename)
    assert file_id

    token = api.get_fileserver_access_token(
        repo.id, file_id, 'download', USER, False)
    url = 'http://127.0.0.1:8082/files/{}/{}'.format(
        token, quote(filename, safe=''))
    headers = {'Range': 'bytes=0-3'} if byte_range else {}
    response = requests.get(url, headers=headers, timeout=30)

    assert response.status_code == (206 if byte_range else 200)
    assert response.content == (content[:4] if byte_range else content)
    disposition = response.headers['Content-Disposition']
    assert disposition.isascii()
    assert disposition.startswith('attachment;')
    # Inspect the fallback parameter directly: parsers may prefer filename*.
    assert re.findall(r';\s*filename="([^"]*)"', disposition) == [expected_filename]
    assert '\r' not in disposition and '\n' not in disposition

    # The extended parameter must still preserve the original filename.
    extended = re.search(r";\s*filename\*=utf-8''([^;]*)", disposition)
    assert extended is not None
    assert unquote(extended.group(1)) == filename
