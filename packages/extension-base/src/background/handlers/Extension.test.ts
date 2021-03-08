// Copyright 2019-2021 @polkadot/extension authors & contributors
// SPDX-License-Identifier: Apache-2.0

import '../../../../../__mocks__/chrome';

import type { ExtDef } from '@polkadot/types/extrinsic/signedExtensions/types';
import keyring from '@polkadot/ui-keyring';
import { cryptoWaitReady } from '@polkadot/util-crypto';

import { AccountsStore } from '../../stores';
import Extension from './Extension';
import State from './State';
import Tabs from './Tabs';
import { MetadataDef } from "@polkadot/extension-inject/types";
import { TypeRegistry } from '@polkadot/types';
import { defaultExtensions } from '@polkadot/types/extrinsic/signedExtensions';
import type { SignerPayloadJSON } from '@polkadot/types/types';

describe('Extension', () => {
  let extension: Extension;
  let state: State;
  let tabs: Tabs;
  const suri = 'seed sock milk update focus rotate barely fade car face mechanic mercy';
  const password = 'passw0rd';

  async function createExtension (): Promise<Extension> {
    await cryptoWaitReady();

    keyring.loadAll({ store: new AccountsStore() });
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
    test('Inject metadata', async () => {
      const types = {
          PaymentOptions: {
            feeExchange: "Option<FeeExchange>",
            tip: "Compact<Balance>"
          },
          FeeExchangeV1: {
            assetId: 'Compact<AssetId>',
            maxPayment: 'Compact<Balance>',
          },
          FeeExchange: {
            _enum: {
              FeeExchangeV1: 'FeeExchangeV1'
            },
          },
        }  as unknown as Record<string, string>;

      const userExtensions =
      {
        ChargeTransactionPayment: {
          payload: {},
          extrinsic: {
            transactionPayment: 'PaymentOptions',
          },
        },
        CheckEra: {
          payload: {
            blockHash: 'Hash',
          },
          extrinsic: {
            era: 'ExtrinsicEra',
          },
        },
        CheckGenesis: {
          payload: {
            genesisHash: 'Hash',
          },
          extrinsic: {},
        },
        CheckNonce: {
          payload: {},
          extrinsic: {
            nonce: 'Compact<Index>',
          },
        },
        CheckSpecVersion: {
          payload: {
            specVersion: 'u32',
          },
          extrinsic: {},
        },
        CheckTxVersion: {
          payload: {
            transactionVersion: 'u32',
          },
          extrinsic: {},
        },
      } as unknown as ExtDef;

      const payload = {
        address: "14u4eV3nAezEdHQb5zP37P2RtxtBdNHsQBaG69Vk42JiuZg",
        blockHash: "0xe1b1dda72998846487e4d858909d4f9a6bbd6e338e4588e5d809de16b1317b80",
        blockNumber: "0x00000393",
        era: "0x3601",
        genesisHash: "0xc6b4596042462b51b589a6b467e77671f738c4c011081aa048333be4945528cf",
        method: "0x040105fa8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a4882380100",
        nonce: "0x0000000000000000",
        signedExtensions: ["CheckSpecVersion", "CheckTxVersion", "CheckGenesis", "CheckMortality", "CheckNonce", "CheckWeight", "ChargeTransactionPayment"],
        specVersion: "0x00000026",
        tip: null,
        transactionVersion: "0x00000005",
        version: 4,
      } as unknown as SignerPayloadJSON;

      const registry = new TypeRegistry();
      let address = await createAccount();
      const pair = keyring.getPair(address);
      pair.decodePkcs8(password);

      const extPayloadWithoutCustomSignedExtension = registry
        .createType('ExtrinsicPayload', payload, { version: payload.version }).sign(pair);
      expect(extPayloadWithoutCustomSignedExtension.signature).toEqual('0x003b6675e62d5739c07ca0b0b846ea558d1064c9dd68e81ad86e0a8f92942b348618d90afe45580f2fd850a994d02cd1c3deeba2ad7680c5872508b342362afb0d');

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
      const allMeta = state.knownMetadata; // get all metadata
      const metaSavedInState = allMeta.find(metaSaved => metaSaved.genesisHash === meta.genesisHash);
      expect(metaSavedInState).toEqual(meta);

      registry.setSignedExtensions(defaultExtensions, metaSavedInState?.userExtensions);

      if (metaSavedInState) {
        registry.register(metaSavedInState?.types);
      }

      const extPayloadWithCustomSignedExtension =  registry
        .createType('ExtrinsicPayload', payload, { version: payload.version }).sign(pair);
      console.log('extPayload:',extPayloadWithCustomSignedExtension);
      expect(extPayloadWithCustomSignedExtension.signature).toEqual('0x000d1cbc1cd03d5e08b569bda81f13a19557ebcb609170965dc48dd4e4014d315c4d98f07c4944b9f0a1e2fad505376a8ccf0d345a545d19102d111de71cc84903');

      // await expect(tabs.handle('id', 'pub(authorize.tab)', {origin: 'cennznet.io'}, 'http://localhost:3000',{} as chrome.runtime.Port)).resolves.toEqual(true);
      // await expect(tabs.handle('id', 'pub(extrinsic.sign)', payload, 'http://localhost:3000',{} as chrome.runtime.Port)).resolves.toEqual(true);


    });
  });
});
