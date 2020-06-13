import socket
import argparse
import threading
import datetime
import time
import smtplib
import poplib
from sntp import NTPPacket


IP = "localhost"

open_udp = []
open_tcp = []
udp_result = []
tcp_result = []


def check_tcp(start, end, domain):
    stamp = datetime.datetime.now()
    print("Начался скан TCP")
    for i in range(start, end):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            try:
                s.connect((domain, i))
                open_tcp.append(i)
            except:
                pass
    print("Скан TCP закончился. Прошло: " + str(datetime.datetime.now() - stamp))


def check_udp(start, end, domain):
    stamp = datetime.datetime.now()
    print("Начался скан UDP")
    for i in range(start, end):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            try:
                s.sendto(b"\x00", (domain, i))
                s.settimeout(0.2)
                _, _ = s.recvfrom(i)
                open_udp.append(i)
            except ConnectionResetError:
                pass
            except socket.timeout:
                pass
    print("Скан UDP закончился. Прошло: " + str(datetime.datetime.now() - stamp))


def check_dns(domain, port, s):
    d = b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    s.sendto(d, (domain, port))
    s.settimeout(0.5)
    data, sender = s.recvfrom(256)
    print(data)
    if data[2: 4] != b"\x01\x00":
        udp_result.append(f"Открыт UDP порт {port}. Протокол: DNS")
        return True


def check_sntp(domain, port, s):
    diff = (datetime.date(1970, 1, 1) - datetime.date(1900, 1, 1)).days * 24 * 3600
    packet = NTPPacket(version_number=2, mode=3, transmit=int(time.time() + diff))
    answer = NTPPacket()
    s.sendto(packet.pack(), (domain, port))
    data, sender = s.recvfrom(512)
    try:
        answer.unpack(data)
        udp_result.append(f"Открые UDP порт {port}. Протокол: ntp")
    except: pass


def check_http(domain, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        s.connect((domain, port))
        try:
            s.send(b"GET / HTTP/1.1 \r\n")
            s.send(b"Accept: */*")
            s.send(b"User-Agent: HTTPClient \r\n")
            s.send(b"\r\n")
            data = s.recv(1024)
            if data.split(b"\r\n")[0][0:4] == b"HTTP":
                tcp_result.append(f"Открыт TCP порт {port}. Протокол: HTTP")
                return True
        except socket.timeout:
            return False
        except ConnectionResetError:
            return False


def check_smtp(domain, port, tcp=False):
    try:
        s = smtplib.SMTP(domain, port, timeout=1)
        s.login("0", "0")
    except socket.timeout:
        return False
    except smtplib.SMTPException:
        if tcp:
            tcp_result.append(f"Открыт TCP порт {port}. Протокол: SMTP")
        else:
            udp_result.append(f"Открыт UDP порт {port}. Протокол: SMTP")
        return True


def check_pop3(domain, port, tcp=False):
    try:
        pop = poplib.POP3(domain, port, timeout=1)
        print(pop.stat())
    except socket.timeout:
        return False
    except poplib.error_proto as e:
        if str(e)[0:6] != "b'-ERR":
            return False
        if tcp:
            tcp_result.append(f"Открыт TCP порт {port}. Протокол: POP3")
        else:
            udp_result.append(f"Открыт UDP порт {port}. Протокол: POP3")
        return True


def check_udp_protocols(domain):
    print("Начата проверка протоколов на UDP портах")
    stamp = datetime.datetime.now()
    for i in open_udp:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.5)
            if check_dns(domain, i, s):
                continue
            if check_sntp(domain, i, s):
                continue
            if check_smtp(domain, i):
                continue
        udp_result.append(f"Открыт UDP порт {i}. Узнать протокол не удалось")
    print(f"Закончена проверка протоколов на UDP. Прошло: {datetime.datetime.now() - stamp}")


def check_tcp_protocols(domain):
    print("Начата проверка протоколов на TCP портах")
    stamp = datetime.datetime.now()
    for i in open_tcp:
        if check_http(domain, i):
            continue
        if check_pop3(domain, i, True):
            continue
        if check_smtp(domain, i, True):
            continue
        tcp_result.append(f"Открыт TCP порт {i}. Узнать протокол не удалось")
    print(f"Закончена проверка протоколов на TCP. Прошло: {datetime.datetime.now() - stamp}")


def main():
    parser = argparse.ArgumentParser(description="TCP/UDP scanner")
    parser.add_argument("start", type=int, help="Порт, с которого начнётся скан")
    parser.add_argument("end", type=int, help="Порт, на котором закончится скан")
    parser.add_argument("domain", default="127.0.0.1", help="Домен, на котором проводится сканирование")
    args = parser.parse_args()
    if args.start > args.end:
        raise ValueError("Начальный порт не может быть больше конечного порта")
    tcp = threading.Thread(target=check_tcp, args=(args.start, args.end + 1, args.domain))
    udp = threading.Thread(target=check_udp, args=(args.start, args.end + 1, args.domain))
    tcp.start(), udp.start()
    tcp.join()
    udp.join()
    tcp_proto = threading.Thread(target=check_tcp_protocols, args=(args.domain,))
    udp_proto = threading.Thread(target=check_udp_protocols, args=(args.domain,))
    tcp_proto.start(), udp_proto.start()
    tcp_proto.join(), udp_proto.join()
    for i in tcp_result:
        print(i)
    for i in udp_result:
        print(i)


if __name__ == "__main__":
    main()
