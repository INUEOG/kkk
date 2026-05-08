import uuid

def get_mac_address_uuid():
    # uuid.getnode()는 시스템의 MAC 주소를 정수로 반환합니다.
    # 이 정수를 16진수 문자열로 변환합니다.
    mac_num = uuid.getnode()
    mac_hex = format(mac_num, '012x') # 12자리의 16진수 (MAC 주소는 6바이트이므로 12자리)

    # 16진수 문자열을 콜론으로 구분된 형태로 포맷팅합니다.
    mac_address = ":".join([mac_hex[i:i+2] for i in range(0, 12, 2)])
    return mac_address

if __name__ == "__main__":
    mac = get_mac_address_uuid()
    print(f"이 장치의 MAC 주소: {mac}")