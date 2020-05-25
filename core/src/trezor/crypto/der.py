if False:
    from typing import List, Tuple


def encode_length(l: int) -> bytes:
    if l < 0x80:
        return bytes([l])
    elif l <= 0xFF:
        return bytes([0x81, l])
    elif l <= 0xFFFF:
        return bytes([0x82, l >> 8, l & 0xFF])
    else:
        raise ValueError


def decode_length(data: bytes, offset: int) -> Tuple[int, int]:
    init = data[offset]
    offset += 1
    if init < 0x80:
        # short form encodes length in initial octet
        return init, offset

    # long form
    n = 0
    for _ in range(init & 0x7F):
        n = n * 0x100 + data[offset]
        offset += 1

    return n, offset


def encode_int(i: bytes) -> bytes:
    i = i.lstrip(b"\x00")
    if i[0] >= 0x80:
        i = b"\x00" + i
    return b"\x02" + encode_length(len(i)) + i


def decode_int(data: bytes, offset: int) -> Tuple[bytes, int]:
    if data[offset] != 0x02:
        raise ValueError
    n, offset = decode_length(data, offset + 1)

    # find first non-null octet
    for i in range(offset, offset + n):
        if data[i]:
            break

    return data[i : offset + n], offset + n


def encode_seq(seq: tuple) -> bytes:
    res = b""
    for i in seq:
        res += encode_int(i)
    return b"\x30" + encode_length(len(res)) + res


def decode_seq(data: bytes, offset: int) -> Tuple[List[bytes], int]:
    if data[offset] != 0x30:
        raise ValueError
    n, offset = decode_length(data, offset + 1)

    seq = []
    end = offset + n
    while offset < end:
        i, offset = decode_int(data, offset)
        seq.append(i)

    if offset != end:
        raise ValueError

    return seq, offset
