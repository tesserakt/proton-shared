import { ADDRESS_TYPE } from '../constants';
import { Key } from './Key';
import { SignedKeyList, SignedKeyListInfo } from './SignedKeyList';

export interface Address {
    DisplayName: string;
    DomainID: string;
    Email: string;
    HasKeys: number;
    ID: string;
    Keys: Key[];
    Order: number;
    Priority: number;
    Receive: number;
    Send: number;
    Signature: string;
    SignedKeyList: SignedKeyListInfo;
    Status: number;
    Type: ADDRESS_TYPE;
}

export interface AddressKey {
    AddressID: string;
    PrivateKey: string;
    SignedKeyList: SignedKeyList;
}

export interface Recipient {
    Name: string;
    Address: string;
    ContactID?: string;
    Group?: string;
}
