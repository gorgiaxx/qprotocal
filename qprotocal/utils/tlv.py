#!/usr/bin/env python
import struct
import binascii
import random

from qprotocal.utils.qqtea import QQTEA


class TLV(object):
    """docstring for TLV"""

    def __init__(self):
        pass

    # to pack tlv.
    def tlv_pack(self, cmd, bin, len_padding=0):
        return struct.pack(">HH", cmd, len(bin) + len_padding) + bin

    # unpack tlv package
    def tlv_unpack(self, qqobj, bin):
        tlv_count = struct.unpack('>H', bin[:2])[0]
        bin = bin[2:]
        for i in range(tlv_count):
            tlv_cmd = bin[:2]
            bin = bin[2:]
            tlv_len = struct.unpack('>H', bin[:2])[0]
            bin = bin[2:]
            tlv_bin = bin[:tlv_len]
            # print('get tlv_cmd', str(binascii.b2a_hex(tlv_cmd))[2:-1])
            bin = bin[tlv_len:]

            # do something by tlv_cmd
            if tlv_cmd == b'\x01\x0A':
                qqobj.token_004c = tlv_bin
            elif tlv_cmd == b'\x01\x6A':
                pass
            elif tlv_cmd == b'\x01\x06':
                pass
            elif tlv_cmd == b'\x01\x0C':
                pass
            elif tlv_cmd == b'\x01\x0D':
                pass
            elif tlv_cmd == b'\x01\x1F':
                pass
            elif tlv_cmd == b'\x01\x20':
                pass
            elif tlv_cmd == b'\x01\x63':
                pass
            elif tlv_cmd == b'\x01\x65':
                pass
            elif tlv_cmd == b'\x01\x18':
                pass
            elif tlv_cmd == b'\x01\x08':
                pass
            elif tlv_cmd == b'\x01\x14':
                qqobj.token_0058 = self.tlv_x114_get0058(tlv_bin)
            elif tlv_cmd == b'\x01\x0E':
                qqobj.mST1_key = tlv_bin
            elif tlv_cmd == b'\x01\x03':
                qqobj.stweb = tlv_bin
            elif tlv_cmd == b'\x01\x38':
                xx_len = tlv_bin[:4]
                pass
            elif tlv_cmd == b'\x01\x1A':
                face = struct.unpack('>H', tlv_bin[:2])[0]
                age = struct.unpack('>B', tlv_bin[2:3])[0]
                gender = struct.unpack('>B', tlv_bin[3:4])[0]
                xx_len = struct.unpack('>B', tlv_bin[4:5])[0]
                tlv_bin = tlv_bin[5:]
                qqobj.nick = tlv_bin[:xx_len].decode('UTF-8')
                print('face:{0},age:{1},gender:{2},nickname:{3}'.format(
                    face, age, gender, qqobj.nick))
            elif tlv_cmd == b'\x01\x20':
                qqobj.skey = tlv_bin
            elif tlv_cmd == b'\x01\x36':
                qqobj.vkey = tlv_bin
            elif tlv_cmd == b'\x03\x05':
                qqobj.session_key = tlv_bin
            elif tlv_cmd == b'\x01\x43':
                qqobj.token_002c = tlv_bin
            elif tlv_cmd == b'\x01\x64':
                qqobj.sid = tlv_bin
            elif tlv_cmd == b'\x01\x30':
                time = struct.unpack('>L', tlv_bin[2:6])[0]
                ip = tlv_bin[6:10]
                print("time:{0},ip:{1}.{2}.{3}.{4}".format(
                    time, ip[3], ip[2], ip[1], ip[0]))
            elif tlv_cmd == b'\x01\x04':
                qqobj.verification_token2 = tlv_bin
            elif tlv_cmd == b'\x01\x05':
                xx_len = struct.unpack('>H', tlv_bin[:2])[0]
                tlv_bin = tlv_bin[2:]
                qqobj.verification_token1 = tlv_bin[:xx_len]
                tlv_bin = tlv_bin[xx_len:]
                xx_len = struct.unpack('>H', tlv_bin[:2])[0]
                tlv_bin = tlv_bin[2:]
                qqobj.verification = tlv_bin[:xx_len]
            elif tlv_cmd == b'\x01\x6C':
                qqobj.pskey = tlv_bin
            elif tlv_cmd == b'\x01\x6D':
                qqobj.superkey = tlv_bin
            else:
                pass
                # print('unknown tlv_cmd', str(binascii.b2a_hex(tlv_cmd)), str(binascii.b2a_hex(tlv_bin)))

    def tlv_x1(self, qq_number, time):
        ip_ver = 1
        random32 = random.randrange(4294967295)
        ip_addr = 0
        tlv_data = struct.pack(">HIIIIH", ip_ver, random32,
                               qq_number, time, ip_addr, 0)
        return self.tlv_pack(0x01, tlv_data)

    def tlv_x2(self, code, verification_token1):
        tlv_data = struct.pack(">I", len(code))
        tlv_data += code.encode('ascii')
        tlv_data += struct.pack(">H", len(verification_token1))
        tlv_data += verification_token1
        return self.tlv_pack(0x02, tlv_data)

    def tlv_x8(self):
        local_id = 0x0804
        tlv_data = struct.pack(">HIH", 0, local_id, 0)
        return self.tlv_pack(0x08, tlv_data)

    def tlv_x18(self, qq_number):
        ping_ver = 1
        sso_ver = 1536
        appid = 0x10
        app_client_ver = 0
        tlv_data = struct.pack(">HIIIIHH", ping_ver,
                               sso_ver, appid, app_client_ver, qq_number, 0, 0)
        return self.tlv_pack(0x18, tlv_data)

    def tlv_x100(self, sub_appid):
        db_buf_ver = 1
        sso_ver = 5
        appid = 0x10
        app_client_version = 0
        main_sigmap = 0x0E10E0
        tlv_data = struct.pack(">HIIIII", db_buf_ver, sso_ver,
                               appid, sub_appid, app_client_version, main_sigmap)
        return self.tlv_pack(0x0100, tlv_data)

    def tlv_x104(self, verification_token2):
        tlv_data = verification_token2
        return self.tlv_pack(0x0104, tlv_data)

    def tlv_x106(self, qq_number, md5_pwd, md5_2_pwd, TGT_key, imei, time, appid):
        TGT_ver = 3
        random32 = random.randrange(4294967295)
        tlv_data = struct.pack(">HIIIIIIII?", TGT_ver,
                               random32, 5, 16, 0, 0, qq_number, time, 0, 1)
        tlv_data += md5_pwd + TGT_key

        tlv_data += struct.pack("I?", 0, 1)
        tlv_data += imei + struct.pack("I", appid)
        tlv_data += struct.pack("IH", 1, 0)
        tlv_data = QQTEA().encrypt(tlv_data, md5_2_pwd)
        return self.tlv_pack(0x0106, tlv_data)

    def tlv_x107(self):
        pic_type = 0
        tlv_data = struct.pack(">H?H?", pic_type, 0, 0, 1)
        return self.tlv_pack(0x0107, tlv_data)

    def tlv_x108(self, ksid):
        # tlv_data = ksid
        tlv_data = b''
        return self.tlv_pack(0x0108, tlv_data)

    def tlv_x109(self, imei):
        tlv_data = imei
        return self.tlv_pack(0x0109, tlv_data)

    def tlv_x114_get0058(self, bin):
        xx_len = struct.unpack('>H', bin[6:8])[0]
        bin = bin[8:xx_len + 8]
        return bin

    def tlv_x116(self):
        m_misc_bit_map = 0x7F7C
        m_sub_sig_map = 0x010400
        sub_appid_list_length = 0
        tlv_data = struct.pack(">?II?", 0, m_misc_bit_map,
                               m_sub_sig_map, sub_appid_list_length)
        return self.tlv_pack(0x0116, tlv_data)

    def tlv_x124(self, os_type, os_version, network_type, apn):
        os_type_len = struct.pack(">H", len(os_type))
        os_version_len = struct.pack(">H", len(os_version))
        network_type = struct.pack(">H", network_type)
        sim_operator_name = bytes(2)
        apn_len = struct.pack(">H", len(apn))
        tlv_data = os_type_len + os_type + os_version_len + \
            os_version + network_type + \
            sim_operator_name + bytes(2) + apn_len + apn
        return self.tlv_pack(0x0124, tlv_data)

    def tlv_x128(self, device, imei):
        new_install = 0
        read_guid = 1
        guid_chg = 0
        dev_report = 0x01000000
        device_len = struct.pack(">H", len(device))
        imei_len = struct.pack(">H", len(imei))
        tlv_data = struct.pack(">H???I", 0, new_install,
                               read_guid, guid_chg, dev_report)
        tlv_data += device_len + device + imei_len + imei + bytes(2)
        return self.tlv_pack(0x0128, tlv_data)

    def tlv_x141(self, network_type, apn):
        ver = 1
        sim_operator_name = 0
        apn_len = len(apn)
        tlv_data = struct.pack(
            ">HHHH", ver, sim_operator_name, network_type, apn_len) + apn
        return self.tlv_pack(0x0141, tlv_data)

    def tlv_x142(self, apk_id):
        tlv_num = struct.pack(">I", len(apk_id))
        tlv_data = tlv_num + apk_id
        return self.tlv_pack(0x0142, tlv_data)

    def tlv_x144(self, TGT_key, tlv109, tlv124, tlv128, tlv16e):
        tlv_num = struct.pack(">H", 4)
        tlv_data = QQTEA().encrypt((tlv_num + tlv109 + tlv124 + tlv128 + tlv16e), TGT_key)
        return self.tlv_pack(0x0144, tlv_data)

    def tlv_x145(self, imei):
        tlv_data = imei
        return self.tlv_pack(0x0145, tlv_data)

    def tlv_x147(self, apk_ver, apk_sig):
        appid = 0x10
        apk_v_len = len(apk_ver)
        apk_sig_len = len(apk_sig)
        tlv_data = struct.pack(">IH", appid, apk_v_len)
        tlv_data += apk_ver
        tlv_data += struct.pack(">H", apk_sig_len)
        tlv_data += apk_sig
        return self.tlv_pack(0x0109, tlv_data)

    def tlv_x154(self, sso_seq):
        tlv_data = struct.pack(">I", sso_seq)
        return self.tlv_pack(0x0154, tlv_data)

    def tlv_x16b(self):
        ver = 1
        url = "game.qq.com".encode('ascii')
        url_len = len(url)
        tlv_data = struct.pack(">HH", ver, url_len) + url
        return self.tlv_pack(0x016b, tlv_data)

    def tlv_x16e(self, device):
        tlv_data = device
        return self.tlv_pack(0x016e, tlv_data)

    def tlv_x177(self):
        qq_ver = "5.2.3.0".encode('ascii')
        qq_ver_len = struct.pack(">H", len(qq_ver))
        tlv_data = b"\x01" + b"\x53\xFB\x17\x9B" + qq_ver_len + qq_ver
        return self.tlv_pack(0x0177, tlv_data)

    def tlv_x187(self):
        tlv_data = b'\xF8\xFF\x12\x23\x6E\x0D\xAF\x24\x97\xCE\x7E\xD6\xA0\x7B\xDD\x68'
        return self.tlv_pack(0x0187, tlv_data)

    def tlv_x188(self):
        tlv_data = b'\x4D\xBF\x65\x33\xD9\x08\xC2\x73\x63\x6D\xE5\xCD\xAE\x83\xC0\x43'
        return self.tlv_pack(0x0188, tlv_data)

    def tlv_x191(self):
        tlv_data = bytes(1)
        return self.tlv_pack(0x0191, tlv_data)
