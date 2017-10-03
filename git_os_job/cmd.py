# Copyright (c) 2013 Doug Hellmann
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import print_function

import argparse
import subprocess
import sys
import webbrowser

import six


def safe_decode(text, incoming=None, errors='strict'):
    """Decodes incoming text/bytes string.

    This is done using `incoming` if they're not already unicode. This code
    originally came from the module oslo.utils:
    http://git.openstack.org/cgit/openstack/oslo.utils/tree/oslo_utils/encodeutils.py#n27

    :param incoming: Text's current encoding
    :param errors: Errors handling policy. See here for valid
        values http://docs.python.org/3/library/codecs.html
    :returns: text or a unicode `incoming` encoded
                representation of it.
    :raises TypeError: If text is not an instance of str
    """
    if not isinstance(text, (six.string_types, six.binary_type)):
        raise TypeError("%s can't be decoded" % type(text))

    if isinstance(text, six.text_type):
        return text

    if not incoming:
        incoming = (sys.stdin.encoding or
                    sys.getdefaultencoding())

    try:
        return text.decode(incoming, errors)
    except UnicodeDecodeError:
        # Note(flaper87) If we get here, it means that
        # sys.stdin.encoding / sys.getdefaultencoding
        # didn't return a suitable encoding to decode
        # text. This happens mostly when global LANG
        # var is not set correctly and there's no
        # default encoding. In this case, most likely
        # python will use ASCII or ANSI encoders as
        # default encodings but they won't be capable
        # of decoding non-ASCII characters.
        #
        # Also, UTF-8 is being used since it's an ASCII
        # extension.
        return text.decode('utf-8', errors)


def main():
    parser = argparse.ArgumentParser(
        description='Show the OpenStack job logs for a commit in a browser',
    )
    parser.add_argument(
        '--base',
        action='store',
        default='http://logs.openstack.org',
        help='base URL, defaults to %(default)s',
    )
    parser.add_argument(
        '-u', '--url',
        action='store_true',
        default=False,
        help='show the URL but do not open it',
    )
    parser.add_argument(
        '-r', '--reverse',
        dest='reverse',
        action='store_true',
        default=False,
        help='given a log URL, show the gerrit URL',
    )
    parser.add_argument(
        'ref',
        nargs='?',
        default='HEAD',
        help='the git reference, tag, or commit, defaults to %(default)s',
    )
    args = parser.parse_args()

    ref = args.ref
    if args.reverse:
        # A log URL looks something like:
        # http://logs.openstack.org/c4/c4afbe14deee6f55378cda53e624c8c6aa9a9d08/release-post/tag-releases/2ea6052/
        try:
            sha = ref.split('/')[4]
        except IndexError:
            parser.abort(
                'Could not parse log URL {}'.format(ref)
            )
        try:
            parents = subprocess.check_output(
                ['git', 'rev-list', '--parents', '-n1', sha]
            ).decode('utf-8').rstrip().split(' ')
        except subprocess.CalledProcessError:
            parser.abort(
                'Could not determine parents of {}'.format(sha)
            )
        if len(parents) == 2:
            # This commit was merged directly into the branch without
            # a separate merge commit. We want to show it, rather than
            # a parent.
            commit = parents[0]
        else:
            # The commit is a merge commit, so we need to show the
            # parent that has the actual patch.
            commit = parents[-1]
        url = 'https://review.openstack.org/#/q/commit:' + commit
    else:
        try:
            ref_hash = safe_decode(subprocess.check_output(
                ['git', 'show-ref', '-s', ref]
            )).rstrip()
        except subprocess.CalledProcessError:
            # Maybe they gave us a commit id
            try:
                ref_hash = safe_decode(subprocess.check_output(
                    ['git', 'show', '--pretty=format:%H', '--quiet', ref]
                )).rstrip()
            except subprocess.CalledProcessError:
                sys.stderr.write('Could not get hash for ref %r\n' % ref)
                return 1

        ref_hash_str = safe_decode(ref_hash)
        url = '%s/%s/%s/' % (args.base, ref_hash_str[:2], ref_hash_str)

    if args.url:
        print(url)
    else:
        webbrowser.open(url)
    return 0


if __name__ == '__main__':
    sys.exit(main())
