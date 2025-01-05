import itertools
import string


def get_charset(charsets : str | list[str]) -> list[str]:
    result = []
    for i in charsets:
        if i == "lowercase":
            result += [char for char in string.ascii_lowercase]
        elif i == "uppercase":
            result += [char for char in string.ascii_uppercase]
        elif i == "numbers":
            result += [char for char in string.digits]
        elif i == "specials":
            result += [char for char in "!#$%&'()@^`{}"]
        else:
            result += [char for char in i if char not in result]
    return result


def get_keyspace(charset : str | list[str], len_min : int, len_max : int, multiple=1) -> int:
    c = len(charset)
    keyspace = 0
    for l in range(len_min, len_max + 1):
        keyspace += c ** l
    return keyspace * multiple


def get_combinations(charset: str | list[str], min : int, max : int) -> list[str]:
    pool = tuple(charset)
    n = len(pool)
    for len_str in range (min, max+1):
        for indices in itertools.product(range(n), repeat=len_str):
            yield "".join(tuple(pool[i] for i in indices))
