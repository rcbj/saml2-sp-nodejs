// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// parseXml refuses what is not well-formed before anything reads it. These inputs were accepted
// under @xmldom/xmldom 0.8; the test holds that 0.9's refusals reach the caller as a library error.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { SamlError } from '../src/index.ts';
import { parseXml } from '../src/xml.ts';

describe('parseXml', () => {
  it('parses a well-formed document', () => {
    assert.equal(parseXml('<a x="1"><b>t</b></a>').documentElement.localName, 'a');
  });

  const refused: Record<string, string> = {
    'an unclosed element': '<a><b></a>',
    'no end tag': '<a>',
    'a mismatched end tag': '<a></b>',
    'text after the root': '<a/>junk',
    'text before the root': 'junk<a/>',
    'a second root': '<a/><b/>',
    'an unbound element prefix': '<p:a/>',
    'an unbound attribute prefix': '<a p:x="1"/>',
    'an unterminated CDATA section': '<a><![CDATA[x</a>',
    'a repeated attribute': '<a x="1" x="2"/>',
    'nothing at all': '',
    'a DOCTYPE': '<!DOCTYPE a><a/>',
  };
  for (const [name, text] of Object.entries(refused)) {
    it(`refuses ${name}`, () => {
      assert.throws(() => parseXml(text), (err: unknown) => err instanceof SamlError && err.code === 'xml');
    });
  }
});
