import io
import struct
import zlib
from typing import Iterator, Tuple, Callable, Set

ResourceLoadFunc = Callable[[], bytes]
ResourceType = int
ResourceGroup = int
ResourceInstance = int
ResourceInfo = Tuple[ResourceType, ResourceGroup, ResourceInstance, ResourceLoadFunc]


def read_package(filename: str, type_filter: Set[ResourceType] = None) -> Iterator[ResourceInfo]:
    type_filter = {} if not type_filter else type_filter
    with open(filename, 'rb') as stream:
        def u32(): return struct.unpack('I', stream.read(4))[0]
        assert stream.read(4).decode('ascii') == 'DBPF'
        stream.seek(32, io.SEEK_CUR)
        index_entry_count = u32()
        stream.seek(24, io.SEEK_CUR)
        index_offset = u32()
        stream.seek(index_offset, io.SEEK_SET)
        index_flags: int = u32()
        static_t: int = u32() if index_flags & 0x1 else 0
        static_g: int = u32() if index_flags & 0x2 else 0
        static_i: int = u32() << 32 if index_flags & 0x4 else 0
        static_i |= u32() if index_flags & 0x8 else 0
        for _ in range(index_entry_count):
            t = static_t if index_flags & 0x1 else u32()
            g = static_g if index_flags & 0x2 else u32()
            instance_hi = static_i >> 32 if index_flags & 0x4 else u32()
            instance_lo = static_i & 0xFFFFFFFF if index_flags & 0x8 else u32()
            i = (instance_hi << 32) + instance_lo
            offset: int = u32()
            sz: int = u32()
            file_size: int = sz & 0x7FFFFFFF
            stream.seek(4, io.SEEK_CUR)
            compressed: bool = sz & 0x80000000 > 0
            compression_type: int = 0
            if compressed:
                compression_type = struct.unpack('H', stream.read(2))[0]
                stream.seek(2, io.SEEK_CUR)
            if compression_type not in (0x0000, 0x5A42):
                continue

            def load_func() -> bytes:
                pos = stream.tell()
                stream.seek(offset, io.SEEK_SET)
                data = stream.read(file_size)
                stream.seek(pos, io.SEEK_SET)
                return zlib.decompress(data) if compression_type == 0x5A42 else data
            if len(type_filter) == 0 or t in type_filter:
                yield t, g, i, load_func
