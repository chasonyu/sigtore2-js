/*
Copyright 2023 The Sigstore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
import { fromPartial } from '@total-typescript/shoehorn';
import assert from 'assert';
import fetch from 'make-fetch-happen';
import { checkStatus, HTTPError } from '../../external/error';

type Response = Awaited<ReturnType<typeof fetch>>;

describe('checkStatus', () => {
  describe('when the response is OK', () => {
    const response: Response = fromPartial({
      status: 200,
      statusText: 'OK',
      ok: true,
    });

    it('returns the response', async () => {
      await expect(checkStatus(response)).resolves.toEqual<Response>(response);
    });
  });

  describe('when the response is not OK', () => {
    const response: Response = fromPartial({
      status: 404,
      statusText: 'Not Found',
      ok: false,
    });

    it('throws an error', async () => {
      expect.assertions(2);
      try {
        await checkStatus(response);
      } catch (e) {
        assert(e instanceof HTTPError);
        expect(e.message).toEqual('(404) Not Found');
        expect(e.statusCode).toEqual(404);
      }
    });
  });

  describe('when the response has a message', () => {
    const response: Response = fromPartial({
      status: 404,
      statusText: 'Not Found',
      ok: false,
      headers: {
        get: (header: string) => {
          if (header === 'Content-Type') {
            return 'application/json';
          }
          if (header === 'Location') {
            return 'https://example.com';
          }
          return undefined;
        },
      },
      json: () => {
        return Promise.resolve({ message: 'record not found' });
      },
    });

    it('throws an error with the message', async () => {
      expect.assertions(3);
      try {
        await checkStatus(response);
      } catch (e) {
        assert(e instanceof HTTPError);
        expect(e.message).toEqual('(404) record not found');
        expect(e.statusCode).toEqual(404);
        expect(e.location).toEqual('https://example.com');
      }
    });
  });
});
