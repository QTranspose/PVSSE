from Crypto.Random import get_random_bytes


def random(l):
    return get_random_bytes(l)


def bytes_xor(a, b):
    result = bytearray(a)
    for i, b_byte in enumerate(b):
        result[i] ^= b_byte
    return bytes(result)


def int_to_bytes(x, output_len=-1):
    if output_len == -1:
        output_len = (x.bit_length() + 7) // 8
    return x.to_bytes(output_len, 'big')


def int_from_bytes(xbytes):
    return int.from_bytes(xbytes, 'big')


def partition_ids(identifier_list: list,
                  entry_count_in_one_block: int,
                  identifier_size: int,
                  block_size_bytes: int = 0):
    if block_size_bytes == 0:
        block_size_bytes = entry_count_in_one_block * identifier_size

    if block_size_bytes < entry_count_in_one_block * identifier_size:
        raise ValueError("Invalid block_size_bytes")

    for i in range(0, len(identifier_list), entry_count_in_one_block):
        block = b''.join(identifier_list[i:i + entry_count_in_one_block])
        if len(block) < block_size_bytes:
            block += b'\x00' * (block_size_bytes - len(block))
        yield block


def parse_ids(block: bytes, entry_count_in_one_block: int):
    identifier_size = len(block) // entry_count_in_one_block
    result = []
    for i in range(0, len(block), identifier_size):
        identifier = block[i:i + identifier_size]
        if identifier == b'\x00' * len(identifier):
            break
        result.append(identifier)
    return result

