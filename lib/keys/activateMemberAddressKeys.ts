import { encryptPrivateKey } from 'pmcrypto';
import { verifySelfAuditResult, KT_STATUS } from 'key-transparency-web-client';
import { Address, Api, DecryptedKey, KeyTransparencyState, UserModel as tsUserModel } from '../interfaces';
import { MEMBER_PRIVATE } from '../constants';
import { getSignedKeyList } from './signedKeyList';
import { activateKeyRoute } from '../api/keys';
import { getActiveKeys } from './getActiveKeys';

export const getAddressesWithKeysToActivate = (user: tsUserModel, addresses: Address[]) => {
    // If signed in as subuser, or not a readable member
    if (!user || !addresses || user.OrganizationPrivateKey || user.Private !== MEMBER_PRIVATE.READABLE) {
        return [];
    }
    return addresses.filter(({ Keys = [] }) => {
        return Keys.some(({ Activation }) => !!Activation);
    });
};

interface Args {
    address: Address;
    addressKeys: DecryptedKey[];
    keyPassword: string;
    api: Api;
    keyTransparencyState?: KeyTransparencyState;
}

export const activateMemberAddressKeys = async ({
    address,
    addressKeys,
    keyPassword,
    api,
    keyTransparencyState,
}: Args) => {
    if (!addressKeys.length) {
        return;
    }
    if (!keyPassword) {
        throw new Error('Password required to generate keys');
    }
    const activeKeys = await getActiveKeys(address.SignedKeyList, address.Keys, addressKeys);
    const ktMessageObject = {
        message: '',
        addressID: address.ID,
    };
    for (const addressKey of addressKeys) {
        const { ID, privateKey } = addressKey;
        const Key = address.Keys.find(({ ID: otherID }) => otherID === ID);
        if (!Key?.Activation || !privateKey) {
            continue;
        }
        const encryptedPrivateKey = await encryptPrivateKey(privateKey, keyPassword);
        const SignedKeyList = await getSignedKeyList(activeKeys);

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
                throw new Error(`Cannot activate key: ${ktInfo.error}`);
            }
            ktMessageObject.message = ktInfo.message;
        }

        await api(activateKeyRoute({ ID, PrivateKey: encryptedPrivateKey, SignedKeyList }));
    }

    return ktMessageObject;
};
