# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/utils/payload.py
import math, os, struct
from typing import Any, Generator, Tuple, Union, Callable, List, Dict
from bitarray import bitarray

def calculate_scales(value: Union[(int, float)], scales: List[Dict[(str, Union[(int, float, None)])]], default: Union[(int, float)]=None, calculator: Callable=None) -> Union[(int, float)]:
    if not callable(calculator):
        raise RuntimeError("invalid calculator: {0}".format(calculator))
    scales = scales or []
    for scale in scales:
        lower = scale.get("minimum")
        upper = scale.get("maximum")
        if upper is not None:
            if lower is not None:
                if lower <= value <= upper:
                    return calculator(value, **scale)
        elif upper is not None:
            if value <= upper:
                return calculator(value, **scale)
        elif lower is not None:
            if lower <= value:
                return calculator(value, **scale)
            else:
                return calculator(value, **scale)
    else:
        if default is not None:
            return default
        raise RuntimeError("{0} does not fall within scalar bounds".format(value))


def generate(keywords, parameters, size=0, endian='little'):
    if len(keywords) != len(parameters):
        msg = "invalid parameter length: expected {0} but got {1}".format(len(parameters), len(keywords))
        raise RuntimeError(msg)
    else:
        size = size or sum([p["bit_length"] for k, p in parameters.items()])
        bits = bitarray(([0] * size), endian=endian)
        for key, param in parameters.items():
            try:
                value = keywords[key]
            except KeyError:
                raise RuntimeError("could not find key: {0}".format(key))
            else:
                mapper = param.get("map")
                if mapper:
                    generator_name = "{0}_generator".format(mapper["calculator"])
                    try:
                        generator = globals()[generator_name]
                    except KeyError:
                        raise NotImplementedError(generator_name)
                    else:
                        kw = {k: v for k, v in mapper.items() if k != "calculator"}
                        raw = generator(value, **kw)
                else:
                    raw = value
                byte_data = pack(raw, (param["data_type"]), bit_length=(param["bit_length"]))
                set_chunk_in_bits(bits, byte_data,
                  byte_position=(param["byte_position"]),
                  bit_position=(param["bit_position"]),
                  bit_length=(param["bit_length"]),
                  endian=endian)

        return bits.tobytes()


def get_chunk_from_bits(bits, byte_position=0, bit_position=0, bit_length=0):
    start = byte_position * 8 + bit_position
    end = start + bit_length
    return bits[start:end].tobytes()


def enum_calculator(value: int, enum: Dict[(str, int)]=None) -> Union[(bool, str, int)]:
    if len(enum) == 2:
        temp_enum = (k.upper() for k in enum.keys())
        if "FALSE" in temp_enum:
            if "TRUE" in temp_enum:
                return value == 1
            for k, v in (enum or {}).items():
                if v == value:
                    return k
            else:
                return value


def enum_generator(key: str, enum: Dict[(str, int)]=None) -> Union[(int, str)]:
    try:
        return (enum or {})[key]
    except KeyError:
        return key


def linear_calculator(value: Union[(int, float)], offset: Union[(int, float)]=0, factor: Union[(int, float)]=0, denominator: Union[(int, float)]=1, minimum: Union[(int, float)]=None, maximum: Union[(int, float)]=None) -> float:
    mapped = (offset + factor * value) / denominator
    if minimum is not None:
        if mapped < minimum:
            return minimum
    if maximum is not None:
        if maximum < mapped:
            return maximum
    return mapped


def linear_generator(value: Union[(int, float)], offset: Union[(int, float)]=0, factor: Union[(int, float)]=1, denominator: Union[(int, float)]=1, minimum: Union[(int, float)]=None, maximum: Union[(int, float)]=None) -> float:
    if minimum is not None:
        if value < minimum:
            value = minimum
    if maximum is not None:
        if maximum < value:
            value = maximum
    return (value * denominator - offset) / float(factor)


def integer_generator(value: Union[(int, float)], offset: Union[(int, float)]=0, factor: Union[(int, float)]=1, denominator: Union[(int, float)]=1, minimum: Union[(int, float)]=None, maximum: Union[(int, float)]=None) -> int:
    if minimum is not None:
        if value < minimum:
            value = minimum
    if maximum is not None:
        if maximum < value:
            value = maximum
    return int((value * denominator - offset) // factor)


def pack(value, data_type, bit_length=None):
    if data_type in ('int', 'uint'):
        if not bit_length:
            bit_length = 32
        return int(value).to_bytes(((bit_length + 7) // 8), byteorder="big", signed=(data_type == "int"))
    else:
        if data_type == "float":
            return struct.pack(">f", float(value))
        else:
            if data_type == "double":
                return struct.pack(">d", float(value))
            if data_type == "bytes":
                if type(value) is int:
                    byte_length = int(math.ceil(bit_length / 8.0))
                    return bytes([value]).rjust(byte_length, b'\x00')
            if data_type in ('ascii', 'utf8'):
                return value.encode(data_type)
        return value


def pad(payload, length, endian='little'):
    padding = b'\x00' * (length - len(payload))
    if endian == "little":
        return padding + payload
    else:
        return payload + padding


def parse(payload: bytes, parameters: dict, endian: str='little') -> Generator[(Tuple[(str, Any)], None, None)]:
    bits = bitarray(endian=endian)
    bits.frombytes(payload)
    for key, param in parameters.items():
        chunk = get_chunk_from_bits(bits,
          byte_position=(param["byte_position"]),
          bit_position=(param["bit_position"]),
          bit_length=(param["bit_length"]))
        raw = unpack(chunk, param["data_type"])
        yield (
         key, parse_value(raw, param))


def parse_value(value: bytes, value_parameters: Dict[(str, Union[(Dict, int, float)])]) -> Union[(bytes, str, int, float)]:
    calculator_name = value_parameters.get("map", {}).get("calculator")
    if calculator_name:
        method_name = calculator_name + "_calculator"
        try:
            calculator = globals()[method_name]
        except KeyError:
            raise NotImplementedError(method_name)
        else:
            kw = {k: v for k, v in value_parameters["map"].items() if k != "calculator"}
            return calculator(value, **kw)
    else:
        return value


def rational_calculator(value: Union[(int, float)], numerators: List[Union[(int, float)]]=None, denominators: List[Union[(int, float)]]=None, minimum: Union[(int, float)]=None, maximum: Union[(int, float)]=None) -> Union[(int, float)]:
    numerator = sum(num * value ** i for i, num in enumerate(numerators))
    denominator = sum(denom * value ** i for i, denom in enumerate(denominators))
    mapped = numerator / float(denominator)
    if maximum is not None:
        if maximum < mapped:
            return maximum
    if minimum is not None:
        if mapped < minimum:
            return minimum
    return mapped


def rational_generator(value: Union[(int, float)], numerators: List[Union[(int, float)]]=None, denominators: List[Union[(int, float)]]=None, minimum: Union[(int, float)]=None, maximum: Union[(int, float)]=None) -> float:
    numerators = numerators or [1]
    denominators = denominators or [1]
    numerator = sum(num * value ** i for i, num in enumerate(numerators))
    denominator = sum(denom * value ** i for i, denom in enumerate(denominators))
    mapped = denominator / float(numerator)
    if maximum is not None:
        if maximum < mapped:
            return maximum
    if minimum is not None:
        if mapped < minimum:
            return minimum
    return mapped


def scale_linear_calculator(value: Union[(int, float)], scales: List[Dict[(str, Union[(int, float, None)])]], default: Union[(int, float)]=None) -> Union[(int, float)]:
    return calculate_scales(value, (scales or []),
      default=default,
      calculator=linear_calculator)


def scale_rational_calculator(value: Union[(int, float)], scales: List[Dict[(str, Union[(int, float, None)])]], default: Union[(int, float)]=None) -> Union[(int, float)]:
    return calculate_scales(value, (scales or []),
      default=default,
      calculator=rational_calculator)


def set_chunk(payload, chunk, byte_position=0, bit_position=0, bit_length=0, endian='little'):
    bits = bitarray(endian=endian)
    bits.frombytes(payload)
    set_chunk_in_bits(bits, chunk,
      byte_position=byte_position,
      bit_position=bit_position,
      bit_length=bit_length,
      endian=endian)
    return bits.tobytes()


def set_chunk_in_bits(bits, chunk, byte_position=0, bit_position=0, bit_length=0, endian='little'):
    start = byte_position * 8 + bit_position
    chunk_bits = bitarray(endian=endian)
    chunk_bits.frombytes(chunk)
    for i in range(bit_length):
        if i < len(chunk_bits):
            bits[start + i] = chunk_bits[i]
        else:
            bits[start + i] = 0


def unpack(payload: bytes, data_type: str, padding: bytes=b'\xff') -> Union[(bytes, str, float, int)]:
    if data_type == "bytes":
        return payload
    else:
        if data_type in ('ascii', 'utf8'):
            return payload.strip(padding).strip(b'\x00').decode("ascii")
        else:
            if data_type == "int":
                return struct.unpack(">i", pad(payload, 4))[0]
            if data_type == "uint":
                return struct.unpack(">I", pad(payload, 4))[0]
            if data_type == "float":
                return struct.unpack(">f", pad(payload, 4))[0]
        if data_type == "double":
            return struct.unpack(">d", pad(payload, 8))[0]
    raise RuntimeError("invalid data type: {0}".format(data_type))


def validate_safe_string(input_str: str, allowed: str):
    if input_str is None:
        return
    if not isinstance(input_str, str):
        raise ValueError("input is not a string")
    for c in input_str:
        if c not in allowed:
            raise ValueError("Character {} is not allowed.".format(c))


def validate_string_length(input_str: str, max_chars: int):
    if len(input_str) > max_chars:
        raise OverflowError("String has too many characters")


def validate_path_absolute(path: str):
    if path is None:
        return
    else:
        if not isinstance(path, str):
            raise ValueError("path is not a string: {}".format(str(path)))
        else:
            if path == "":
                raise ValueError("empty path")
            raise os.path.isabs(path) or ValueError("path is not absolute: {}".format(path))
        if ".." in path:
            raise ValueError("path traversing with .. not allowed: {}".format(path))

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/utils/payload.pyc
