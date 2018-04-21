import struct
import socket
from spec_cache import Cache


port = 53
ip = '127.0.0.2'
timeout_sec = 7
cache = Cache()
types = {1: 'A', 2: 'NS'}


class DNSPacket:
    """defining DNS packet here"""

    def __init__(self, data):
        self.data = data
        self.transaction_id = data[:2]
        self.flags = data[2:4]
        self.questions = int.from_bytes(data[4:6], 'big')
        self.answer_rrs = int.from_bytes(data[6:8], 'big')
        self.authority_rrs = int.from_bytes(data[8:10], 'big')
        self.additional_rrs = int.from_bytes(data[10:12], 'big')

        query, cursor_loc = self.get_queries()
        self.query = query

        self.point = cursor_loc
        self.answers = []
        self.auth = []

        if self.answer_rrs != 0:
            for i in range(self.answer_rrs):
                answer, index = self.get_answers(12 + cursor_loc, data[12 + cursor_loc:])
                self.answers.append(answer)
                cache.append(query.name, answer, answer.type)
                cursor_loc += index

        if self.authority_rrs != 0:
            for i in range(self.authority_rrs):
                answer, index = self.get_answers(12 + cursor_loc, self.data[cursor_loc + 12:])
                self.auth.append(answer)
                cache.append(query.name, answer, answer.type)
                cursor_loc += index

        # self.answers, cursor_loc = self.fill_fields_in(self.answer_rrs, self.answers, cursor_loc)
        # self.auth, cursor_loc = self.fill_fields_in(self.authority_rrs, self.auth, cursor_loc)

    def fill_fields_in(self, count_rrs, list_rss, point):
        if count_rrs != 0:
            for i in range(count_rrs):
                answer, index = self.get_answers(12 + point, data[12 + point:])
                list_rss.append(answer)
                cache.append(query.name, answer, answer.type)
                point += index
        return list_rss, point

    def get_answers(self, point, data):
        bytes_readed, domain_name = self.get_domain_name(point, self.data)
        type = types[int.from_bytes(data[bytes_readed:bytes_readed + 2], 'big')]
        class_int = int.from_bytes(data[bytes_readed + 2:bytes_readed + 4], 'big')
        ttl = int.from_bytes(data[bytes_readed + 4:bytes_readed + 8], 'big')
        data_len = int.from_bytes(data[bytes_readed + 8:bytes_readed + 10], 'big')
        _data = data[:bytes_readed+10+data_len]
        answer = Answer(domain_name, type, class_int, ttl, _data)
        return answer, bytes_readed + 10 + data_len

    def get_queries(self):
        data = self.data[12:]
        index, domain_name = self.get_domain_name(0, data)
        type = types[int.from_bytes(data[index + 1:index + 3], 'big')]
        class_int = int.from_bytes(data[index + 3:index + 5], 'big')
        query = Query(domain_name, type, class_int, data[:index + 5])
        return query, index + 5

    def get_domain_name(self, d_index, data):
        index = d_index
        domain_name = ''
        current_byte = data[index]
        while current_byte != 0:
            count_symbol = data[index]
            if count_symbol == 192:
                point = int.from_bytes(data[index:index + 2], 'big')
                _, name = self.get_domain_name(point - 49152, data)
                return index + 2 - d_index, domain_name + name
            for i in range(count_symbol):
                domain_name += chr(data[1 + index + i])
            index += 1 + count_symbol
            current_byte = data[index]
            domain_name += '.'
        return index - d_index, domain_name

    def pack(self):
        result = self.transaction_id + b'\x81\x80' + b'\x00\x01'
        answers_bytes = b''
        auth_bytes = b''
        count_answ_rrs = 0
        count_auth_rrs = 0
        if self.query.type in cache.cache[self.query.name]:
            count_answ_rrs = len(cache.cache[self.query.name][self.query.type])
            for answ in cache.cache[self.query.name][self.query.type]:
                answers_bytes += answ[0].full_bytes_record

        count_addt_rrs = self.additional_rrs.to_bytes(2, byteorder='big')
        result += struct.pack('!h', count_answ_rrs) + \
                  struct.pack('!h', count_auth_rrs) + \
                  count_addt_rrs + \
                  query.full_bytes_record
        result += answers_bytes + auth_bytes
        return result


class Answer:
    def __init__(self, name, type_answ,  class_int, ttl, byte):
        self.name = name
        self.type = type_answ
        self.ttl = ttl
        self.class_int = class_int
        self.full_bytes_record = byte

    def __str__(self):
        return """ name: {0}, type: {1}, class_int: {2}, ttl: {3}""".format(
            self.name,
            self.type,
            self.class_int,
            self.ttl)


class Query:
    def __init__(self, name, type, inter, byte):
        self.name = name
        self.type = type
        self.class_int = inter
        self.full_bytes_record = byte

    def __str__(self):
        return """ Domain_Name: {0}, Type: {1}, Class_int: {2}"""\
                .format(self.name, self.type, self.class_int)


def readdress(data):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(data, ('212.193.163.7', 53))
    s.settimeout(5)
    try:
        print("got online")
        data = s.recv(1024)
        return data
    except socket.timeout:
        print("Timeout")
    except Exception as e:
        print(e)
    s.close()


with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind((ip, port))
    sock.settimeout(timeout_sec)

    while True:
        try:
            data, addr = sock.recvfrom(1024)
        except socket.timeout:
            print('Timeout. Server is shutting down')
            cache.save_cache()
            break
        dns_packet = DNSPacket(data)
        query, _ = dns_packet.get_queries()
        if query in cache:
            print("cached info")
            data_to_send = dns_packet.pack()
        else:
            data_to_send = readdress(data)
            DNSPacket(data_to_send)

        sock.sendto(data_to_send, addr)
