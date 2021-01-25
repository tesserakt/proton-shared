import { OpenPGPKey, getKeys } from 'pmcrypto';
import { verifySelfAuditResult, KT_STATUS } from 'key-transparency-web-client';
import { srpVerify } from '../srp';
import { setupKeys } from '../api/keys';
import { Api, Address, KeyTransparencyState } from '../interfaces';
import { generateKeySaltAndPassphrase } from './keys';
import { getResetAddressesKeys, getResetAddressesKeysV2 } from './resetKeys';
import { hasAddressKeyMigration } from '../constants';

interface Args {
    api: Api;
    addresses: Address[];
    password: string;
    keyTransparencyState?: KeyTransparencyState;
}

export const handleSetupKeys = async ({ api, addresses, password, keyTransparencyState }: Args) => {
    if (!addresses.length) {
        throw new Error('An address is required to setup keys');
    }
    const { passphrase, salt } = await generateKeySaltAndPassphrase(password);

    const { userKeyPayload, addressKeysPayload } = hasAddressKeyMigration
        ? await getResetAddressesKeysV2({
              addresses,
              passphrase,
          })
        : await getResetAddressesKeys({ addresses, passphrase });

    await srpVerify({
        api,
        credentials: { password },
        config: setupKeys({
            KeySalt: salt,
            PrimaryKey: userKeyPayload,
            AddressKeys: addressKeysPayload,
        }),
    });

    // Prepare keys
    const userPublicKeys = (await getKeys(userKeyPayload)).map((privateKey: OpenPGPKey) => privateKey.toPublic());
    const ktMessageObjects = await Promise.all(
        addressKeysPayload.map(async ({ AddressID, SignedKeyList }) => {
            const ktMessageObject = {
                message: '',
                addressID: AddressID,
            };
            const address = addresses.find((address) => address.ID === AddressID);
            if (!address) {
                throw new Error('Address for KT not found');
            }
            if (keyTransparencyState) {
                const ktInfo = await verifySelfAuditResult(
                    address,
                    SignedKeyList,
                    keyTransparencyState.ktSelfAuditResult,
                    keyTransparencyState.lastSelfAudit,
                    keyTransparencyState.isRunning,
                    api
                );

                if (ktInfo.code === KT_STATUS.KT_FAILED) {
                    throw new Error(`Cannot import key: ${ktInfo.error}`);
                }
                ktMessageObject.message = ktInfo.message;
            }
            return ktMessageObject;
        })
    );

    return { keyPassword: passphrase, userPublicKeys, ktMessageObjects };
};
