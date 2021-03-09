// Copyright 2019-2021 @polkadot/extension authors & contributors
// SPDX-License-Identifier: Apache-2.0

import '../../../../../__mocks__/chrome';

import type { ExtDef } from '@polkadot/types/extrinsic/signedExtensions/types';
import keyring from '@polkadot/ui-keyring';
import { cryptoWaitReady } from '@polkadot/util-crypto';

import { AccountsStore } from '../../stores';
import Extension from './Extension';
import State, { AuthUrls } from './State';
import Tabs from './Tabs';
import { MetadataDef } from "@polkadot/extension-inject/types";
import type { SignerPayloadJSON } from '@polkadot/types/types';
import { ResponseSigning } from "@polkadot/extension-base/background/types";

describe('Extension', () => {
  let extension: Extension;
  let state: State;
  let tabs: Tabs;
  const suri = 'seed sock milk update focus rotate barely fade car face mechanic mercy';
  const password = 'passw0rd';

  async function createExtension (): Promise<Extension> {
    await cryptoWaitReady();

    keyring.loadAll({ store: new AccountsStore() });
    let authUrls: AuthUrls = {};
    authUrls['localhost:3000'] = {
      count: 0,
      id: '11',
      isAllowed: true,
      origin: 'cennznet.io',
      url: 'http://localhost:3000'
    };
    localStorage.setItem('authUrls', JSON.stringify(authUrls));
    state = new State();
    tabs = new Tabs(state);
    return new Extension(state);
  }

  const createAccount = async (): Promise<string> => {
    await extension.handle('id', 'pri(accounts.create.suri)', {
      name: 'parent',
      password,
      suri
    }, {} as chrome.runtime.Port);
    const { address } = await extension.handle('id', 'pri(seed.validate)', {
      suri
    }, {} as chrome.runtime.Port);

    return address;
  };

  beforeAll(async () => {
    extension = await createExtension();
  });

  test('exports account from keyring', async () => {
    const { pair: { address } } = keyring.addUri(suri, password);
    const result = await extension.handle('id', 'pri(accounts.export)', {
      address,
      password
    }, {} as chrome.runtime.Port);

    expect(result.exportedJson).toContain(address);
    expect(result.exportedJson).toContain('"encoded"');
  });

  describe('account derivation', () => {
    let address: string;

    beforeEach(async () => {
      address = await createAccount();
    });

    test('pri(derivation.validate) passes for valid suri', async () => {
      const result = await extension.handle('id', 'pri(derivation.validate)', {
        parentAddress: address,
        parentPassword: password,
        suri: '//path'
      }, {} as chrome.runtime.Port);

      expect(result).toStrictEqual({
        address: '5FP3TT3EruYBNh8YM8yoxsreMx7uZv1J1zNX7fFhoC5enwmN',
        suri: '//path'
      });
    });

    test('pri(derivation.validate) throws for invalid suri', async () => {
      await expect(extension.handle('id', 'pri(derivation.validate)', {
        parentAddress: address,
        parentPassword: password,
        suri: 'invalid-path'
      }, {} as chrome.runtime.Port)).rejects.toStrictEqual(new Error('"invalid-path" is not a valid derivation path'));
    });

    test('pri(derivation.validate) throws for invalid password', async () => {
      await expect(extension.handle('id', 'pri(derivation.validate)', {
        parentAddress: address,
        parentPassword: 'invalid-password',
        suri: '//path'
      }, {} as chrome.runtime.Port)).rejects.toStrictEqual(new Error('invalid password'));
    });

    test('pri(derivation.create) adds a derived account', async () => {
      await extension.handle('id', 'pri(derivation.create)', {
        name: 'child',
        parentAddress: address,
        parentPassword: password,
        password,
        suri: '//path'
      }, {} as chrome.runtime.Port);
      expect(keyring.getAccounts()).toHaveLength(2);
    });

    test('pri(derivation.create) saves parent address in meta', async () => {
      await extension.handle('id', 'pri(derivation.create)', {
        name: 'child',
        parentAddress: address,
        parentPassword: password,
        password,
        suri: '//path'
      }, {} as chrome.runtime.Port);
      expect(keyring.getAccount('5FP3TT3EruYBNh8YM8yoxsreMx7uZv1J1zNX7fFhoC5enwmN')?.meta.parentAddress).toEqual(address);
    });
  });

  describe('account management', () => {
    let address: string;

    beforeEach(async () => {
      address = await createAccount();
    });

    test('pri(accounts.changePassword) changes account password', async () => {
      const newPass = 'pa55word';
      const wrongPass = 'ZZzzZZzz';

      await expect(extension.handle('id', 'pri(accounts.changePassword)', {
        address,
        newPass,
        oldPass: wrongPass
      }, {} as chrome.runtime.Port)).rejects.toStrictEqual(new Error('oldPass is invalid'));

      await expect(extension.handle('id', 'pri(accounts.changePassword)', {
        address,
        newPass,
        oldPass: password
      }, {} as chrome.runtime.Port)).resolves.toEqual(true);

      const pair = keyring.getPair(address);

      expect(pair.decodePkcs8(newPass)).toEqual(undefined);

      expect(() => {
        pair.decodePkcs8(password);
      }).toThrowError('Unable to decode using the supplied passphrase');
    });
  });

  describe('custom user extension', () => {
    let address: string, payload: SignerPayloadJSON;

    beforeEach(async () => {
      address = await createAccount();
      payload = {
        address,
        blockHash: "0xe1b1dda72998846487e4d858909d4f9a6bbd6e338e4588e5d809de16b1317b80",
        blockNumber: "0x00000393",
        era: "0x3601",
        genesisHash: "0x242a54b35e1aad38f37b884eddeb71f6f9931b02fac27bf52dfb62ef754e5e62",
        method: "0x040105fa8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a4882380100",
        nonce: "0x0000000000000000",
        signedExtensions: ["CheckSpecVersion", "CheckTxVersion", "CheckGenesis", "CheckMortality", "CheckNonce", "CheckWeight", "ChargeTransactionPayment"],
        specVersion: "0x00000026",
        tip: null,
        transactionVersion: "0x00000005",
        version: 4,
      } as unknown as SignerPayloadJSON;
    });

    test('signs with default signed extensions', async () => {

      tabs.handle('1615191860871.5', 'pub(extrinsic.sign)', payload, 'http://localhost:3000',{} as chrome.runtime.Port)
        .then((result ) => {
          expect((result as ResponseSigning)?.signature).toEqual('0x0002400e60569625020f56ad5a354fffcf56f340e1ccb359713ea4214108684737ea1fa8759e61b2c46b060623b55db16ab850cbeb3419787352331fe934f4e702')
        });

      await expect(extension.handle('1615192072290.7', 'pri(signing.approve.password)', {
        id: state.allSignRequests[0].id,
        password,
        savePass: false
      }, {} as chrome.runtime.Port)).resolves.toEqual(true);

    });

    test('signs with user extensions, known types', async () => {
      const types = {
        PaymentOptions: {
          feeExchange: "FeeExchangeV1",
          tip: "Compact<Balance>"
        },
        FeeExchangeV1: {
          assetId: 'Compact<AssetId>',
          maxPayment: 'Compact<Balance>',
        },
      }  as unknown as Record<string, string>;

      const userExtensions = {
          ChargeTransactionPayment: {
            payload: {},
            extrinsic: {
              transactionPayment: 'PaymentOptions',
            },
          },
      } as unknown as ExtDef;

      const meta: MetadataDef = {
        chain: "Development",
        genesisHash: "0x242a54b35e1aad38f37b884eddeb71f6f9931b02fac27bf52dfb62ef754e5e62",
        icon: "",
        ss58Format: 0,
        tokenDecimals: 12,
        tokenSymbol: "",
        types,
        userExtensions,
        color: "#191a2e",
        specVersion: 38
      };
      state.saveMetadata(meta);

      tabs.handle('1615191860771.5', 'pub(extrinsic.sign)', payload, 'http://localhost:3000',{} as chrome.runtime.Port)
        .then((result ) => {
          expect((result as ResponseSigning)?.signature).toEqual('0x00bb42e63cb8214678a4c045c1832f4a1889393c68fd971f9bbcce0d13837a66b4b3ba3757827c33fbb06158d85440d8f9939208bddc3bf9b13d685162ebf57c0e')
        });

      await expect(extension.handle('1615192062290.7', 'pri(signing.approve.password)', {
        id: state.allSignRequests[0].id,
        password,
        savePass: false
      }, {} as chrome.runtime.Port)).resolves.toEqual(true);

    });

    test('signs with user extensions, additional types', async () => {

      const types = {
        myCustomType: {
            feeExchange: 'Compact<AssetId>',
            tip: 'Compact<Balance>'
          },
        }  as unknown as Record<string, string>;

      const userExtensions = {
        MyUserExtension: {
          payload: {},
          extrinsic: {
            myCustomType: 'myCustomType',
          },
        },
      } as unknown as ExtDef;

      const meta: MetadataDef = {
        chain: "Development",
        genesisHash: "0x242a54b35e1aad38f37b884eddeb71f6f9931b02fac27bf52dfb62ef754e5e62",
        icon: "",
        ss58Format: 0,
        tokenDecimals: 12,
        tokenSymbol: "",
        types,
        userExtensions,
        color: "#191a2e",
        specVersion: 38
      };
      state.saveMetadata(meta);

      const payload = {
        address,
        blockHash: "0xe1b1dda72998846487e4d858909d4f9a6bbd6e338e4588e5d809de16b1317b80",
        blockNumber: "0x00000393",
        era: "0x3601",
        genesisHash: "0x242a54b35e1aad38f37b884eddeb71f6f9931b02fac27bf52dfb62ef754e5e62",
        method: "0x040105fa8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a4882380100",
        nonce: "0x0000000000000000",
        signedExtensions: ["MyUserExtension", "CheckTxVersion", "CheckGenesis", "CheckMortality", "CheckNonce", "CheckWeight", "ChargeTransactionPayment"],
        specVersion: "0x00000026",
        tip: null,
        transactionVersion: "0x00000005",
        version: 4,
      } as unknown as SignerPayloadJSON;

      tabs.handle('1615191860771.5', 'pub(extrinsic.sign)', payload, 'http://localhost:3000',{} as chrome.runtime.Port)
        .then((result ) => {
          expect((result as ResponseSigning)?.signature).toEqual('0x00d5740b2f51c93f762d253a8fb16ed73e8475f1306f8e9852d716247cfaff3561ff10027f3cdee5a349a7da4a0eba281f375f10540a5ea3016dc4c45a4bda9004')
        });

      await expect(extension.handle('1615192062290.7', 'pri(signing.approve.password)', {
        id: state.allSignRequests[0].id,
        password,
        savePass: false
      }, {} as chrome.runtime.Port)).resolves.toEqual(true);
    });
  });
});
