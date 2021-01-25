import { verifySelfAuditResult, KT_STATUS } from 'key-transparency-web-client';
import { removeKeyRoute, setKeyFlagsRoute, setKeyPrimaryRoute } from '../api/keys';
import { Address, Api, DecryptedKey, KeyTransparencyState } from '../interfaces';
import { getSignedKeyList } from './signedKeyList';
import { getActiveKeys } from './getActiveKeys';

export const setPrimaryAddressKey = async (
    api: Api,
    address: Address,
    keys: DecryptedKey[],
    ID: string,
    keyTransparencyState?: KeyTransparencyState
) => {
    const activeKeys = await getActiveKeys(address.SignedKeyList, address.Keys, keys);
    const oldActiveKey = activeKeys.find(({ ID: otherID }) => ID === otherID);
    if (!oldActiveKey) {
        throw new Error('Cannot set primary key');
    }
    const updatedActiveKeys = activeKeys
        .map((activeKey) => {
            return {
                ...activeKey,
                primary: activeKey.ID === ID ? 1 : 0,
            } as const;
        })
        .sort((a, b) => b.primary - a.primary);
    const signedKeyList = await getSignedKeyList(updatedActiveKeys);

    const ktMessageObject = {
        message: '',
        addressID: address.ID,
    };
    if (keyTransparencyState) {
        const ktInfo = await verifySelfAuditResult(
            address,
            signedKeyList,
            keyTransparencyState.ktSelfAuditResult,
            keyTransparencyState.lastSelfAudit,
            keyTransparencyState.isRunning,
            api
        );

        if (ktInfo.code === KT_STATUS.KT_FAILED) {
            throw new Error(`Cannot set primary key: ${ktInfo.error}`);
        }
        ktMessageObject.message = ktInfo.message;
    }

    await api(setKeyPrimaryRoute({ ID, SignedKeyList: signedKeyList }));

    return ktMessageObject;
};

export const deleteAddressKey = async (
    api: Api,
    address: Address,
    keys: DecryptedKey[],
    ID: string,
    keyTransparencyState?: KeyTransparencyState
) => {
    const activeKeys = await getActiveKeys(address.SignedKeyList, address.Keys, keys);
    const oldActiveKey = activeKeys.find(({ ID: otherID }) => ID === otherID);
    if (oldActiveKey?.primary) {
        throw new Error('Cannot delete primary key');
    }
    const updatedActiveKeys = activeKeys.filter(({ ID: otherID }) => ID !== otherID);
    const signedKeyList = await getSignedKeyList(updatedActiveKeys);

    const ktMessageObject = {
        message: '',
        addressID: address.ID,
    };
    if (keyTransparencyState) {
        const ktInfo = await verifySelfAuditResult(
            address,
            signedKeyList,
            keyTransparencyState.ktSelfAuditResult,
            keyTransparencyState.lastSelfAudit,
            keyTransparencyState.isRunning,
            api
        );

        if (ktInfo.code === KT_STATUS.KT_FAILED) {
            throw new Error(`Cannot delete key: ${ktInfo.error}`);
        }
        ktMessageObject.message = ktInfo.message;
    }

    await api(removeKeyRoute({ ID, SignedKeyList: signedKeyList }));

    return ktMessageObject;
};

export const setAddressKeyFlags = async (
    api: Api,
    address: Address,
    keys: DecryptedKey[],
    ID: string,
    flags: number,
    keyTransparencyState?: KeyTransparencyState
) => {
    const activeKeys = await getActiveKeys(address.SignedKeyList, address.Keys, keys);
    const updatedActiveKeys = activeKeys.map((activeKey) => {
        if (activeKey.ID === ID) {
            return {
                ...activeKey,
                flags,
            };
        }
        return activeKey;
    });
    const signedKeyList = await getSignedKeyList(updatedActiveKeys);

    const ktMessageObject = {
        message: '',
        addressID: address.ID,
    };
    if (keyTransparencyState) {
        const ktInfo = await verifySelfAuditResult(
            address,
            signedKeyList,
            keyTransparencyState.ktSelfAuditResult,
            keyTransparencyState.lastSelfAudit,
            keyTransparencyState.isRunning,
            api
        );

        if (ktInfo.code === KT_STATUS.KT_FAILED) {
            throw new Error(`Cannot change flag: ${ktInfo.error}`);
        }
        ktMessageObject.message = ktInfo.message;
    }

    await api(setKeyFlagsRoute({ ID, Flags: flags, SignedKeyList: signedKeyList }));

    return ktMessageObject;
};
