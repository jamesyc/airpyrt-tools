import hashlib
import secrets
from typing import NamedTuple, Optional

from .exception import ACPClientError

MIN_SRP_MODULUS_BITS = 1024
MILLER_RABIN_ROUNDS = 16

_SMALL_PRIMES = (
    3,
    5,
    7,
    11,
    13,
    17,
    19,
    23,
    29,
    31,
    37,
    41,
    43,
    47,
    53,
    59,
    61,
    67,
    71,
    73,
    79,
    83,
    89,
    97,
)


class SRPGroupValidation(NamedTuple):
    known_name: Optional[str]
    bits: int
    generator: int
    fingerprint: str


def _bytes_from_hex(value):
    return bytes.fromhex("".join(value.split()))


RFC5054_1024_N = _bytes_from_hex(
    "eeaf0ab9adb38dd69c33f80afa8fc5e86072618775ff3c0b9ea2314c9c256576"
    "d674df7496ea81d3383b4813d692c6e0e0d5d8e250b98be48e495c1d6089dad1"
    "5dc7d7b46154d6b6ce8ef4ad69b15d4982559b297bcf1885c529f566660e57ec"
    "68edbc3c05726cc02fd4cbf4976eaa9afd5138fe8376435b9fc61d2fc0eb06e3"
)

RFC5054_1536_N = _bytes_from_hex(
    "9def3cafb939277ab1f12a8617a47bbbdba51df499ac4c80beeea9614b19cc4d"
    "5f4f5f556e27cbde51c6a94be4607a291558903ba0d0f84380b655bb9a22e8dc"
    "df028a7cec67f0d08134b1c8b97989149b609e0be3bab63d47548381dbc5b1fc"
    "764e3f4b53dd9da1158bfd3e2b9c8cf56edf019539349627db2fd53d24b7c486"
    "65772e437d6c7f8ce442734af7ccb7ae837c264ae3a9beb87f8a2fe9b8b5292e"
    "5a021fff5e91479e8ce7a28c2442c6f315180f93499a234dcf76e3fed135f9bb"
)

RFC5054_2048_N = _bytes_from_hex(
    "ac6bdb41324a9a9bf166de5e1389582faf72b6651987ee07fc3192943db56050"
    "a37329cbb4a099ed8193e0757767a13dd52312ab4b03310dcd7f48a9da04fd50"
    "e8083969edb767b0cf6095179a163ab3661a05fbd5faaae82918a9962f0b93b8"
    "55f97993ec975eeaa80d740adbf4ff747359d041d5c33ea71d281e446b14773b"
    "ca97b43a23fb801676bd207a436c6481f1d2b9078717461a5b9d32e688f87748"
    "544523b524b0d57d5ea77a2775d2ecfa032cfbdbf52fb3786160279004e57ae6"
    "af874e7303ce53299ccc041c7bc308d82a5698f3a8d0c38271ae35f8e9dbfbb6"
    "94b5c803d89f7ae435de236d525f54759b65e372fcd68ef20fa7111f9e4aff73"
)

RFC5054_3072_N = _bytes_from_hex(
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"
    "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437"
    "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
    "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05"
    "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb"
    "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b"
    "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718"
    "3995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33"
    "a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7"
    "abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864"
    "d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e2"
    "08e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffff"
)

RFC5054_4096_N = _bytes_from_hex(
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"
    "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437"
    "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
    "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05"
    "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb"
    "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b"
    "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718"
    "3995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33"
    "a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7"
    "abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864"
    "d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e2"
    "08e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d7"
    "88719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8"
    "dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2"
    "233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa9"
    "93b4ea988d8fddc186ffb7dc90a6c08f4df435c934063199ffffffffffffffff"
)

RFC5054_6144_N = _bytes_from_hex(
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"
    "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437"
    "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
    "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05"
    "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb"
    "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b"
    "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718"
    "3995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33"
    "a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7"
    "abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864"
    "d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e2"
    "08e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d7"
    "88719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8"
    "dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2"
    "233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa9"
    "93b4ea988d8fddc186ffb7dc90a6c08f4df435c93402849236c3fab4d27c7026"
    "c1d4dcb2602646dec9751e763dba37bdf8ff9406ad9e530ee5db382f413001ae"
    "b06a53ed9027d831179727b0865a8918da3edbebcf9b14ed44ce6cbaced4bb1b"
    "db7f1447e6cc254b332051512bd7af426fb8f401378cd2bf5983ca01c64b92ec"
    "f032ea15d1721d03f482d7ce6e74fef6d55e702f46980c82b5a84031900b1c9e"
    "59e7c97fbec7e8f323a97a7e36cc88be0f1d45b7ff585ac54bd407b22b4154aa"
    "cc8f6d7ebf48e1d814cc5ed20f8037e0a79715eef29be32806a1d58bb7c5da76"
    "f550aa3d8a1fbff0eb19ccb1a313d55cda56c9ec2ef29632387fe8d76e3c0468"
    "043e8f663f4860ee12bf2d5b0b7474d6e694f91e6dcc4024ffffffffffffffff"
)

RFC5054_8192_N = _bytes_from_hex(
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"
    "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437"
    "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
    "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05"
    "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb"
    "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b"
    "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718"
    "3995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33"
    "a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7"
    "abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864"
    "d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e2"
    "08e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d7"
    "88719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8"
    "dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2"
    "233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa9"
    "93b4ea988d8fddc186ffb7dc90a6c08f4df435c93402849236c3fab4d27c7026"
    "c1d4dcb2602646dec9751e763dba37bdf8ff9406ad9e530ee5db382f413001ae"
    "b06a53ed9027d831179727b0865a8918da3edbebcf9b14ed44ce6cbaced4bb1b"
    "db7f1447e6cc254b332051512bd7af426fb8f401378cd2bf5983ca01c64b92ec"
    "f032ea15d1721d03f482d7ce6e74fef6d55e702f46980c82b5a84031900b1c9e"
    "59e7c97fbec7e8f323a97a7e36cc88be0f1d45b7ff585ac54bd407b22b4154aa"
    "cc8f6d7ebf48e1d814cc5ed20f8037e0a79715eef29be32806a1d58bb7c5da76"
    "f550aa3d8a1fbff0eb19ccb1a313d55cda56c9ec2ef29632387fe8d76e3c0468"
    "043e8f663f4860ee12bf2d5b0b7474d6e694f91e6dbe115974a3926f12fee5e4"
    "38777cb6a932df8cd8bec4d073b931ba3bc832b68d9dd300741fa7bf8afc47ed"
    "2576f6936ba424663aab639c5ae4f5683423b4742bf1c978238f16cbe39d652d"
    "e3fdb8befc848ad922222e04a4037c0713eb57a81a23f0c73473fc646cea306b"
    "4bcbc8862f8385ddfa9d4b7fa2c087e879683303ed5bdd3a062b3cf5b3a278a6"
    "6d2a13f83f44f82ddf310ee074ab6a364597e899a0255dc164f31cc50846851d"
    "f9ab48195ded7ea1b1d510bd7ee74d73faf36bc31ecfa268359046f4eb879f92"
    "4009438b481c6cd7889a002ed5ee382bc9190da6fc026e479558e4475677e9aa"
    "9e3050e2765694dfc81f56e880b96e7160c980dd98edd3dfffffffffffffffff"
)

KNOWN_SRP_GROUPS = {
    (RFC5054_1024_N, 2): "RFC 5054 1024-bit group",
    (RFC5054_1536_N, 2): "RFC 5054 1536-bit group",
    (RFC5054_2048_N, 2): "RFC 5054 2048-bit group",
    (RFC5054_3072_N, 5): "RFC 5054 3072-bit group",
    (RFC5054_4096_N, 5): "RFC 5054 4096-bit group",
    (RFC5054_6144_N, 5): "RFC 5054 6144-bit group",
    (RFC5054_8192_N, 19): "RFC 5054 8192-bit group",
}


def srp_group_fingerprint(modulus_bytes):
    return hashlib.sha256(modulus_bytes).hexdigest()


def _is_probable_prime(value, rounds=MILLER_RABIN_ROUNDS):
    if value < 2:
        return False
    if value == 2:
        return True
    if value % 2 == 0:
        return False

    for prime in _SMALL_PRIMES:
        if value == prime:
            return True
        if value % prime == 0:
            return False

    exponent = value - 1
    powers_of_two = 0
    while exponent % 2 == 0:
        powers_of_two += 1
        exponent //= 2

    for _ in range(rounds):
        base = 2 + secrets.randbelow(value - 3)
        check = pow(base, exponent, value)
        if check in (1, value - 1):
            continue

        for _ in range(powers_of_two - 1):
            check = pow(check, 2, value)
            if check == value - 1:
                break
        else:
            return False

    return True


def validate_srp_group(modulus_bytes, generator):
    fingerprint = srp_group_fingerprint(modulus_bytes)
    known_name = KNOWN_SRP_GROUPS.get((modulus_bytes, generator))
    bits = int.from_bytes(modulus_bytes, "big").bit_length()
    validation = SRPGroupValidation(
        known_name=known_name,
        bits=bits,
        generator=generator,
        fingerprint=fingerprint,
    )
    if known_name is not None:
        return validation

    modulus = int.from_bytes(modulus_bytes, "big")
    if bits < MIN_SRP_MODULUS_BITS:
        raise ACPClientError(
            f"unknown SRP group modulus is too small: {bits} bits "
            f"(minimum {MIN_SRP_MODULUS_BITS})",
        )
    if not _is_probable_prime(modulus):
        raise ACPClientError("unknown SRP group modulus is not a probable prime")

    subgroup_order = (modulus - 1) // 2
    if not _is_probable_prime(subgroup_order):
        raise ACPClientError("unknown SRP group modulus is not a probable safe prime")
    if pow(generator, 2, modulus) == 1 or pow(generator, subgroup_order, modulus) == 1:
        raise ACPClientError("unknown SRP group generator is not valid for a safe-prime group")

    return validation
