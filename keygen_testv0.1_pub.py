import math
import random
from datetime import datetime, timedelta

class MathPass:
    HASH_CODE_1 = 0b1000001011100001
    HASH_CODE_2 = 0b1000001100100101
    MAGIC_NUMBER_LIST = [59222]
    hash_val = 59222

    def __init__(self, math_id, version='14.1.0', custom_key=None):
        self.version = MathPass.get_version_code(version)
        self.math_id = None
        self.set_math_id(math_id)
        
        fmt = self.activation_key_format()
        if custom_key and MathPass.check_format(fmt, custom_key):
            self.activation_key = custom_key
        else:
            self.activation_key = MathPass.random_activation_key(fmt)
            
        MathPass.hash_val = 59222
        self.password = ''

    def version_compare(self, major, minor=0, patch=0):
        return (self.version[0] > major) or \
            (self.version[0] == major and self.version[1] > minor) or \
            (self.version[0] == major and self.version[1] == minor and self.version[2] >= patch)

    def activation_key_format(self):
        if self.version_compare(14, 1, 0):
            return 'xxxx-xxxx-aaaaaa'
        else:
            return 'xxxx-xxxx-xxxxxx'

    def set_activation_key(self, key):
        fmt = self.activation_key_format()
        if key and MathPass.check_format(fmt, key):
            self.activation_key = key
        else:
            self.activation_key = MathPass.random_activation_key(fmt)

    def check_password(self, password=None, hash_code=None, mute=False):
        if password is None:
            password = self.password
        if hash_code is None:
            hash_code = MathPass.hash_val
        if self.version_compare(14, 1, 0):
            return self.__check_password_v14_1_0(password, hash_code, mute)
        return False

    def __check_password_v14_1_0(self, password, hash_code, mute):
        if not MathPass.check_format('xxxx-xxx-xxx::bbbbbb:xxxxxxxx', password):
            return False
        parts = password.split(':')
        pass_str = parts[0]
        mathNum = parts[2]
        expireDate = parts[3]
        str_val = self.math_id + '@' + expireDate + '$' + mathNum + '&' + self.activation_key
        n1, n2 = MathPass.__extract_password(pass_str)
        n0 = (n1 + 0x8D06) % 65536
        hash1 = hash_code
        hash2 = MathPass.__encoding_hash(n1)
        characters = [ord(c) for c in reversed(str_val)]
        test1 = MathPass.__decoding_characters(MathPass.HASH_CODE_1, hash1, characters, n0)
        test2 = MathPass.__decoding_characters(MathPass.HASH_CODE_2, hash2, characters, n2)
        return test1 and test2

    def generate_password(self, math_num='800001', expire_date=None):
        if expire_date is None:
            expire_date = MathPass.get_date_after(999)
        if self.version_compare(14, 1, 0):
            return self.__generate_password_v14_1_0(math_num, expire_date)
        return False

    def __generate_password_v14_1_0(self, math_num, expire_date):
        str_val = self.math_id + '@' + expire_date + '$' + math_num + '&' + self.activation_key
        characters = [ord(c) for c in reversed(str_val)]
        hash_code = MathPass.hash_val
        n0 = MathPass.__encoding_characters(MathPass.HASH_CODE_1, hash_code, characters)
        n1 = (n0 + 0x72FA) % 65536
        hash_code = MathPass.__encoding_hash(n1)
        n2 = MathPass.__encoding_characters(MathPass.HASH_CODE_2, hash_code, characters)
        self.password = MathPass.__construct_password(n1, n2) + '::' + math_num + ':' + expire_date
        return True

    @staticmethod
    def __hasher(hasher_code, hash_val, byte_val):
        for _ in range(8):
            bit = byte_val & 1
            if (hash_val % 2) == bit:
                hash_val >>= 1
            else:
                hash_val >>= 1
                hash_val ^= hasher_code
            byte_val >>= 1
        return hash_val

    @staticmethod
    def __split_hex(hex_val):
        n = math.floor(hex_val * 99999.0 / 0xFFFF)
        slice_arr = []
        for _ in range(5):
            slice_arr.append(int(n % 10))
            n = math.floor(n / 10)
        return slice_arr

    @staticmethod
    def __encoding_hash(n1):
        n1 = math.floor(n1 * 99999.0 / 0xFFFF)
        n1_01 = n1 % 100
        n1 -= n1_01
        n1_2 = n1 % 1000
        n1 -= n1_2
        n1 += n1_01 * 10 + n1_2 / 100.0
        temp = int(math.ceil(n1 * 65535.0 / 99999))
        return MathPass.__hasher(
            MathPass.HASH_CODE_2,
            MathPass.__hasher(MathPass.HASH_CODE_2, 0, temp & 0xFF), temp >> 8)

    @staticmethod
    def __encoding_characters(hasher_code, hash_val, characters):
        for char in characters:
            hash_val = MathPass.__hasher(hasher_code, hash_val, char)
        c1 = c2 = 0
        for c1 in range(256):
            for c2 in range(256):
                if MathPass.__hasher(hasher_code, MathPass.__hasher(hasher_code, hash_val, c1), c2) == 0xA5B6:
                    return c1 | (c2 << 8)
        return c1 | (c2 << 8)

    @staticmethod
    def __decoding_characters(hasher_code, hash_val, characters, target):
        for char in characters:
            hash_val = MathPass.__hasher(hasher_code, hash_val, char)
        c1 = target & 0xFF
        c2 = target >> 8
        return MathPass.__hasher(hasher_code, MathPass.__hasher(hasher_code, hash_val, c1), c2) == 0xA5B6

    @staticmethod
    def __construct_password(n1, n2):
        n1str = MathPass.__split_hex(n1)[::-1]
        n2str = MathPass.__split_hex(n2)[::-1]
        return f"{n2str[3]}{n1str[3]}{n1str[1]}{n1str[0]}-{n2str[4]}{n1str[2]}{n2str[0]}-{n2str[2]}{n1str[4]}{n2str[1]}"

    @staticmethod
    def __extract_password(password):
        n1 = int(password[3] + password[2] + password[6] + password[1] + password[10])
        n2 = int(password[7] + password[11] + password[9] + password[0] + password[5])
        return [int(math.ceil(n1 * 65535.0 / 99999)), int(math.ceil(n2 * 65535.0 / 99999))]

    @staticmethod
    def check_format(format_str, s, exact=True):
        if len(format_str) != len(s): return False
        for i in range(len(format_str)):
            if format_str[i] == 'x':
                if not ('0' <= s[i] <= '9'): return False
            elif format_str[i] == 'a':
                if not ('A' <= s[i] <= 'Z'): return False
            elif format_str[i] == 'b':
                if not ('0' <= s[i] <= '9' or 'A' <= s[i] <= 'Z'): return False
            elif format_str[i] != s[i]:
                return False
        return True

    def set_math_id(self, math_id):
        if MathPass.check_format('xxxx-xxxxx-xxxxx', math_id):
            self.math_id = math_id
            return True
        return False

    @staticmethod
    def random_activation_key(fmt='xxxx-xxxx-aaaaaa'):
        res = ""
        for char in fmt:
            if char == 'x':
                res += str(random.randint(0, 9))
            elif char == 'a':
                res += chr(random.randint(65, 90))
            else:
                res += char
        return res

    @staticmethod
    def get_version_code(version):
        parts = version.split('.')
        return [int(parts[0]), int(parts[1]), int(parts[2])]

    @staticmethod
    def get_date_after(days):
        date = datetime.now() + timedelta(days=days)
        return date.strftime("%Y%m%d")

if __name__ == "__main__":
    mid = input("Math ID (xxxx-xxxxx-xxxxx): ")
    custom_key = input("Activation Key (Generates a random one if you leave blank.Format xxxx-xxxx-aaaaaa): ").strip()
    expire_date = input("Expiry Date (YYYYMMDD, Default 999 days after now): ").strip()
    
    mp = MathPass(mid, "14.1.0", custom_key if custom_key else None)
    
    if not expire_date:
        expire_date = None
    
    mp.generate_password(expire_date=expire_date)
    
    print(f"Activation Key: {mp.activation_key}")
    print(f"Password: {mp.password}")
