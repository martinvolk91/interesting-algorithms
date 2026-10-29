"""Keyword PIR for caller ID on the toy BFV: the idea behind Apple's Live Caller ID Lookup.

A phone looks up the label of an incoming number ("Spam", a business name, ...) in a
server's database without the server learning the number. One encrypted query, one
encrypted response, built only from plaintext-ciphertext products and rotations.
Real deployments differ in many ways; see ../deep_dives/bfv_pir.md.
"""
import hashlib
import random

import toy_bfv as bfv

BUCKETS = bfv.N                 # one bucket per slot: bucket b lives in row b // ROW, column b % ROW
ENTRIES = 4                     # (tag, label) pairs per bucket
WORDS = 2 * ENTRIES             # slots a bucket occupies in the response

LABELS = {1: "Spam", 2: "Telemarketer", 3: "Pizza Napoli", 4: "Dr. Weber's practice",
          5: "City Library", 6: "Bike repair shop"}


def h(number, salt):
    return int.from_bytes(hashlib.sha256(f"{salt}:{number}".encode()).digest()[:8], "big")


def bucket_of(number):
    return h(number, "bucket") % BUCKETS


def tag_of(number):
    return 1 + h(number, "tag") % (bfv.T - 1)                 # 1..256; 0 marks an empty entry


def slot_of(bucket, offset=0):
    """Slot holding word `offset` of `bucket` (after the server shifts word w right by w)."""
    row, col = divmod(bucket, bfv.ROW)
    return row * bfv.ROW + (col + offset) % bfv.ROW


# ---------------------------------------------------------------- server side
def build_database(entries):
    """Hash every number into a bucket, then store word w of every bucket in plaintext w."""
    table = [[] for _ in range(BUCKETS)]
    for number, label in entries.items():
        b = bucket_of(number)
        if len(table[b]) == ENTRIES:
            raise ValueError(f"bucket {b} overflows (real systems use cuckoo hashing)")
        table[b].append((tag_of(number), label))
    plaintexts = []
    for w in range(WORDS):
        slots = [0] * bfv.N
        for b, bucket in enumerate(table):
            if w // 2 < len(bucket):
                slots[slot_of(b)] = bucket[w // 2][w % 2]
        plaintexts.append(bfv.encode(slots))
    return table, plaintexts


def answer(query, plaintexts, evk):
    """Mask every plaintext with the encrypted one-hot query, so only the requested bucket
    survives, and shift word w right by w so the whole bucket fits in one ciphertext."""
    response = bfv.mul_plain(query, plaintexts[0])
    for w in range(1, WORDS):
        part = bfv.mul_plain(query, plaintexts[w])
        response = bfv.add(response, bfv.rotate(part, bfv.ROW - w, evk))
    return response


# ---------------------------------------------------------------- client side
def make_query(pk, number):
    one_hot = [0] * bfv.N
    one_hot[slot_of(bucket_of(number))] = 1
    return bfv.encrypt(pk, bfv.encode(one_hot))


def read_answer(s, response, number):
    slots = bfv.decode(bfv.decrypt(s, response))
    words = [slots[slot_of(bucket_of(number), w)] for w in range(WORDS)]
    for tag, label in zip(words[0::2], words[1::2]):
        if tag == tag_of(number):
            return label
    return None


# ---------------------------------------------------------------- demo
if __name__ == "__main__":
    random.seed(11)
    numbers = [f"+1-202-555-01{i:02d}" for i in range(100)]   # 555-01xx: reserved for fiction
    database = {n: random.choice(list(LABELS)) for n in random.sample(numbers, 60)}
    table, plaintexts = build_database(database)

    # client: keys once; the server gets the public key and the Galois keys, never s
    s, pk, evk = bfv.keygen(rotations=[bfv.ROW - w for w in range(1, WORDS)])
    ct_bytes = 2 * bfv.N * bfv.LOG_Q // 8
    gk_bytes = len(evk["galois"]) * bfv.DIGITS * ct_bytes
    print(f"database: {len(database)} numbers in {BUCKETS} buckets of {ENTRIES}, "
          f"{len(plaintexts)} plaintexts of {bfv.N} slots")
    print(f"query {ct_bytes} B, response {ct_bytes} B, Galois keys (sent once) {gk_bytes // 1024} KB")

    print("\n== lookups")
    in_db = list(database)
    for number in [in_db[0], in_db[1], in_db[2], next(n for n in numbers if n not in database)]:
        query = make_query(pk, number)                          # the server sees only this
        response = answer(query, plaintexts, evk)               # the same work for every query
        label = read_answer(s, response, number)
        truth = LABELS.get(database.get(number), "unknown")
        print(f"{number}: bucket {bucket_of(number):>2} -> {LABELS.get(label, 'unknown'):<22}"
              f"(truth: {truth:<22}) response budget {bfv.noise_budget(s, response):.1f} bits")

    print("\n== what the client also learns: the whole bucket (PIR protects the client, not the server)")
    number = in_db[0]
    slots = bfv.decode(bfv.decrypt(s, answer(make_query(pk, number), plaintexts, evk)))
    words = [slots[slot_of(bucket_of(number), w)] for w in range(WORDS)]
    print(f"bucket {bucket_of(number)} as (tag, label) pairs:", list(zip(words[0::2], words[1::2])))
