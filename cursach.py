import struct

with open('packets-file.pcapng', 'rb+') as f:
    # Перемещаемся к началу пакета 1532
    f.seek(0)
    for i in range(1532):
        block_type, block_len = struct.unpack('!HH', f.read(4))
        f.seek(block_len - 4, 1)

    # Теперь мы находимся в начале пакета 1532
    block_type, block_len = struct.unpack('!HH', f.read(4))
    if block_type == 0x00000003:  # Блок данных
        current_zip_data = f.read(block_len - 16)
        # Теперь `current_zip_data` содержит текущее содержимое zip-архива

        with open('maybeconfidential.zip', 'rb') as f:
            new_zip_data = f.read()

        new_block_len = len(new_zip_data) + 16

        f.seek(-block_len, 1)
        f.write(struct.pack('!HH', 0x00000003, new_block_len))
        f.write(new_zip_data)
        f.write(struct.pack('!HH', 0x00000003, new_block_len))

        if new_block_len < block_len:
            f.write(b'\x00' * (block_len - new_block_len))
