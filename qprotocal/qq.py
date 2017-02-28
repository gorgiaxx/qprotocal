#!/usr/bin/env python
# -*- coding: utf-8 -*-

from qprotocal import (QQObject)
from qprotocal.utils.xbin import Xbin
from qprotocal.utils.qqtea import QQTEA
from qprotocal.utils.tlv import TLV
import socket
import struct
import time
import binascii


class QQ(QQObject):

    def __init__(self, qq_number, qq_password):
        self.caption = qq_number
        self.qq_number = int(qq_number)
        self.qq_number_long = struct.pack('>L', self.qq_number)
        self.qq_password = qq_password
        self.md5_pwd = Xbin.get_md5_value(self.qq_password.encode('UTF-8'), 1)
        self.md5_2_pwd = Xbin.get_md5_value(
            self.md5_pwd + bytes(4) + bytes().fromhex(hex(self.qq_number)[2:]), 1)
        self.ksid = bytes().fromhex('93AC689396D57E5F9496B81536AAFE91')

        self.imei = b'866819027236657'
        self.apk_ver = b'5.8.0.157158'
        self.share_key = bytes().fromhex('957C3AAFBF6FAF1D2C2F19A5EA04E51C')
        self.pub_key = bytes().fromhex('02244B79F2239755E73C73FF583D4EC5625C19BF8095446DE1')
        self.appid = 537042771
        self.pc_ver = b'\x1F\x41'
        self.os_type = b'android'
        self.os_version = b'4.4.4'
        self.network_type = 2
        self.apn = b'wifi'
        self.device = b'Nexus 5'
        self.apk_id = b'com.tencent.mobileqq'
        self.apk_sig = b'\xA6\xB7\x45\xBF\x24\xA2\xC2\x77\x52\x77\x16\xF6\xF3\x6E\xB6\x8D'
        self.time = round(time.time())
        self.TGT_key = Xbin().get_random_hex(16, 1)
        self.rand_key = Xbin().get_random_hex(16, 1)

        # sso_seq
        self.request_id = 10000
        self.pc_sub_cmd = 0

        # sessions
        self.token_002c = b''
        self.token_004c = b''
        self.token_0058 = b''
        self.session_key = bytes(16)

        # login state
        # 0 logining, 1 verify, 2 success
        self.login_state = 0
        self.last_error = ''

        # account info
        self.nick = ''
        self.key = b''
        self.skey = b''
        self.vkey = b''
        self.sid = b''
        self.verification = b''
        self.verification_token1 = b''
        self.verification_token2 = b''
        self.pskey = b''
        self.superkey = b''

        tencent_host = socket.gethostbyname('msfwifi.3g.qq.com')
        tencent_port = 8080
        self.s = socket.socket()
        self.s.settimeout(3)
        try:
            self.s.connect((tencent_host, tencent_port))
        except Exception as e:
            raise print('Time out!')

    def __pack(self, bin, type):
        if type == 0:
            package = b'\x00\x00\x00\x08\x02\x00\x00\x00\x04'
        elif type == 1:
            package = b'\x00\x00\x00\x08\x02\x00\x00'
            package += struct.pack('>H',
                                   len(self.token_002c) + 4) + self.token_002c
        else:
            package = b'\x00\x00\x00\x09\x01'
            package += struct.pack('>I', self.request_id)
        package += b'\x00\x00\x00'
        package += struct.pack('>H', len(self.caption) + 4) + \
            self.caption.encode("ascii") + bin
        package = struct.pack('>I', len(package) + 4) + package
        return package

    def __unpack(self, package, flag=0):
        pos1 = package.find(self.caption.encode('ascii'))
        package = package[pos1 + len(self.caption):]
        if flag:
            package = package[pos1 + len(self.caption):]
        return package

    def __send_package(self, package):
        # increase_sso_seq
        if self.request_id > 2147483647:
            self.request_id = 10000
        self.request_id += 1

        # send tcp package
        try:
            # print(str(binascii.b2a_hex(package)))
            self.s.sendall(package)
        except Exception as e:
            raise print('Time out!')
        try:
            recv_data = self.s.recv(2048)
            if len(recv_data) == 0:
                print('Empty Package!!!!!')
                return self.login_state
            if len(recv_data) == 1440:
                while True:
                    tmp_data = self.s.recv(2048)
                    recv_data += tmp_data
                    if len(tmp_data) < 1440:
                        break
            print('recived_len: ', len(recv_data))
            # self.__recive_package(recv_data)
            # self.s.close()
            return recv_data
        except Exception as e:
            raise print('wrong!!!!!')

    def __recive_package(self, package):
        if len(package) == 0:
            raise print('empty!!!!!')
        bin = self.__unpack(package)
        bin = QQTEA().decrypt(bin, self.session_key)
        head_len = struct.unpack('>L', bin[:4])[0]
        # split data
        body_bin = bin[head_len:]
        bin = bin[4:head_len]
        ssq_seq = struct.unpack('>L', bin[:4])[0]
        bin = bin[4:]
        if bin[:4] == bytes(4):
            bin = bin[8:]
        else:
            bin = bin[4:]
            foo_len = struct.unpack('>L', bin[:4])[0]
            bin = bin[4:]
            print('as4: ', foo_len)
            bin = bin[:foo_len - 4]
            print('as5: ', str(binascii.b2a_hex(bin)))

        foo_len = struct.unpack('>L', bin[:4])[0]
        service_cmd = bin[4:foo_len].decode('ascii')
        # Login or other operations
        if service_cmd == 'wtlogin.login':
            bin = body_bin[4:]

            foo_len = struct.unpack('>H', bin[1:3])[0]
            result = struct.unpack('>B', bin[15:16])[0]
            print('result: ', result)
            bin = bin[16:]
            bin = bin[:foo_len - 17]
            bin = QQTEA().decrypt(bin, self.share_key)

            if result != 0:
                if result == 2:
                    self.__unpack_verification_img(bin)
                    self.last_error = "需要输入验证码！"
                    self.login_state = 1
                    bin = b''
                else:
                    self.__unpack_error_msg(bin)
                    self.login_state = 0
                    bin = b''

            # print('fuckbin1111: ', str(binascii.b2a_hex(bin)))
            if len(bin) == 0:
                return False
            bin = bin[7:]

            bin_len = struct.unpack('>H', bin[:2])[0]
            bin = bin[2:]
            # print('fucklen: ', bin_len)
            bin = bin[:bin_len]
            bin = QQTEA().decrypt(bin, self.TGT_key)
            TLV().tlv_unpack(self, bin)
            self.key = self.session_key
            self.login_state = 2
            return True
        else:
            print('service_cmd: ', service_cmd)
            self.__msg_handle(ssq_seq, service_cmd, body_bin)

    def __unpack_verification_img(self, bin):
        TLV().tlv_unpack(self, bin[3:])

    def __msg_handle(self, ssq_seq, service_cmd, body_bin):
        foo_len = struct.unpack('>L', body_bin[:4])[0]
        body_bin = body_bin[4:]
        foo_bin = struct.unpack('>L', body_bin[:foo_len])[0]
        if service_cmd == 'OidbSvc.0x7a2_0':
            pass
        elif service_cmd == 'friendlist.getFriendGroupList':
            pass
        elif service_cmd == 'EncounterSvc.ReqGetEncounter':
            pass
        elif service_cmd == 'friendlist.getUserAddFriendSetting':
            pass
        elif service_cmd == 'SummaryCard.ReqCondSearch':
            pass
        elif service_cmd == 'friendlist.GetAutoInfoReq':
            pass
        elif service_cmd == 'SQQzoneSvc.getMainPage':
            pass
        elif service_cmd == 'friendlist.addFriend':
            pass
        elif service_cmd == 'ProfileService.GroupMngReq':
            pass
        elif service_cmd == 'OnlinePush.PbPushGroupMsg':
            pass
        elif service_cmd == 'MessageSvc.PushReaded':
            pass
        elif service_cmd == 'MessageSvc.PushNotify':
            pass
        elif service_cmd == 'StatSvc.get':
            pass
        elif service_cmd == 'SummaryCard.ReqSummaryCard':
            pass
        elif service_cmd == 'ConfigPushSvc.PushReq':
            pass
        elif service_cmd == 'OidbSvc.0x4ff_9':
            pass
        elif service_cmd == 'QQServiceDiscussSvc.ReqGetDiscuss':
            pass
        elif service_cmd == 'account.RequestReBindMobile':
            pass
        elif service_cmd == 'Signature.auth':
            pass
        elif service_cmd == 'SQQzoneSvc.publishmess':
            pass
        elif service_cmd == 'VisitorSvc.ReqFavorite':
            pass
        elif service_cmd == 'friendlist.GetSimpleOnlineFriendInfoReq':
            pass
        elif service_cmd == 'FriendList.GetTroopListReqV2':
            pass
        elif service_cmd == 'friendlist.getTroopMemberList':
            pass
        elif service_cmd == 'QQServiceDiscussSvc.ReqCreateDiscuss':
            pass
        elif service_cmd == 'QQServiceDiscussSvc.ReqAddDiscussMember':
            pass
        elif service_cmd == 'SQQzoneSvc.getApplist':
            pass
        elif service_cmd == 'friendlist.GetSimpleOnlineFriendInfoReq':
            pass
        elif service_cmd == 'friendlist.GetSimpleOnlineFriendInfoReq':
            pass

    def __pack_login_sso_msg(self, service_cmd, wup_buffer, token, is_login):
        msg_cookies = b'\xB6\xCC\x78\xFC'
        package = struct.pack('>IIIIIII', self.request_id, self.appid,
                              self.appid, 0x01000000, 0, 0, len(token) + 4)

        package += token
        package += struct.pack('>I', len(service_cmd) + 4) + service_cmd
        package += struct.pack('>I', len(msg_cookies) + 4) + msg_cookies
        package += struct.pack('>I', len(self.imei) + 4) + self.imei
        # package += struct.pack('>I', len(self.ksid) + 4) + self.ksid
        package += struct.pack('>I', 4)
        package += struct.pack('>H', len(self.apk_ver) + 2) + self.apk_ver
        package = struct.pack('>I', len(package) + 4) + package

        package += struct.pack('>I', len(wup_buffer) + 4) + wup_buffer
        # 4
        package = self.__pack(QQTEA().encrypt(
            package, self.session_key), is_login ^ 0)
        return package

    def __unpack_error_msg(self, bin):
        bin = bin[9:]
        err_type = bin[:4]
        title_len = struct.unpack('>H', bin[4:6])[0]
        bin = bin[6:]
        title = bin[:title_len].decode('UTF-8')
        bin = bin[title_len:]
        message_len = struct.unpack('>H', bin[:2])[0]
        bin = bin[2:]
        message = bin[:message_len].decode('UTF-8')
        self.last_error = "{0}:{1}".format(title, message)

    def __increase_pc_sub_cmd(self):
        if self.pc_sub_cmd > 2147483647:
            self.pc_sub_cmd = 10000
        self.pc_sub_cmd += 1

    def __pack_package(self, tlv_package):
        tlv_data = self.pc_ver + struct.pack(">HHI", 0x0810, self.pc_sub_cmd, self.qq_number) + \
            b'\x03\x07\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00'
        pub_key_len = len(self.pub_key)
        if pub_key_len > 0:
            tlv_data += b'\x01\x01'
        else:
            tlv_data += b'\x01\x02'
        tlv_data += self.rand_key + b'\x01\x02' + \
            struct.pack(">H", pub_key_len)
        if pub_key_len > 0:
            tlv_data += self.pub_key
        else:
            tlv_data += struct.pack(">H", 0)

        # obj = self
        bin = QQTEA().encrypt(tlv_package, self.share_key)

        tlv_data += bin + b'\x03'
        tlv_pack = b'\x02' + struct.pack(">H", len(tlv_data) + 3) + tlv_data

        return tlv_pack

    def __pack_tlv_x2(self, code):
        tlv_data = TLV().tlv_x2(code, self.verification_token1)
        tlv_data += TLV().tlv_x8()
        tlv_data += TLV().tlv_x104(self.verification_token2)
        tlv_data += TLV().tlv_x116()

        cmd = struct.pack(">H", 2)
        tlv_num = struct.pack(">H", 4)
        return cmd + tlv_num + tlv_data

    def __pack_tlv_x9(self):
        tlv_data = TLV().tlv_x18(self.qq_number)

        tlv_data += TLV().tlv_x1(self.qq_number, self.time)
        tlv_data += TLV().tlv_x106(self.qq_number, self.md5_pwd, self.md5_2_pwd,
                                   self.TGT_key, self.imei, self.time, self.appid)

        tlv_data += TLV().tlv_x116()
        tlv_data += TLV().tlv_x100(self.appid)
        tlv_data += TLV().tlv_x108(self.ksid)
        tlv_data += TLV().tlv_x107()

        # tlv_x144
        tlv_x109 = TLV().tlv_x109(self.imei)
        tlv_x124 = TLV().tlv_x124(
            self.os_type, self.os_version, self.network_type, self.apn)

        tlv_x128 = TLV().tlv_x128(self.device, self.imei)
        tlv_x16e = TLV().tlv_x16e(self.device)

        tlv_data += TLV().tlv_x144(self.TGT_key,
                                   tlv_x109, tlv_x124, tlv_x128, tlv_x16e)
        tlv_data += TLV().tlv_x142(self.apk_id)
        tlv_data += TLV().tlv_x145(self.imei)
        tlv_data += TLV().tlv_x154(self.request_id)
        tlv_data += TLV().tlv_x141(self.network_type, self.apn)
        tlv_data += TLV().tlv_x8()
        tlv_data += TLV().tlv_x16b()
        tlv_data += TLV().tlv_x147(self.apk_ver, self.apk_sig)
        tlv_data += TLV().tlv_x177()
        tlv_data += TLV().tlv_x187()
        tlv_data += TLV().tlv_x188()
        tlv_data += TLV().tlv_x191()

        cmd = struct.pack(">H", 9)
        tlv_num = struct.pack(">H", 19)
        return cmd + tlv_num + tlv_data

    def login(self):
        tlv_package = self.__pack_tlv_x9()
        wup_buffer = self.__pack_package(tlv_package)

        # first login
        self.__increase_pc_sub_cmd()
        recv_data = self.__send_package(self.__pack_login_sso_msg(
            b'wtlogin.login', wup_buffer, b'', 1))
        self.__recive_package(recv_data)
        return self.login_state

    def send_code(self, code):
        tlv_package = self.__pack_tlv_x2(code)
        wup_buffer = self.__pack_package(tlv_package)
        recv_data = self.__send_package(self.__pack_login_sso_msg(
            b'wtlogin.login', wup_buffer, b'', 1))
        self.__recive_package(recv_data)
        return self.login_state

    def heart_beats(self):
        pass
