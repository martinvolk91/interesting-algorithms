from gmpy2 import is_prime, next_prime, gcd
import random


def generate_prime(bits):
    candidate = random.randrange(2 ** (bits - 2), 2 ** bits) | 1
    while not is_prime(candidate):
        candidate = next_prime(candidate)
    return candidate


def find_e(num_phi):
    num_e = 2

    while True:
        # e must be co-prime to phi and
        # smaller than phi.
        if gcd(num_e, num_phi) == 1:
            break
        else:
            num_e = num_e + 1

    return num_e


def mod_inverse(e, phi):
    return pow(e, -1, phi)


# Generate a 2048-bit prime number
p = generate_prime(2048)
# p = 61
q = generate_prime(2048)
# q = 53

print(f"p: {p}")
print(f"q: {q}")

n = p * q
print(f"n: {n}")

phi = (p - 1) * (q - 1)
print(f"phi: {phi}")

# e = find_e(phi)
# standard value is 65537
e = 65537
print(f"e: {e}")

d = mod_inverse(e, phi)
print(f"d: {d}")

print()

message = "hello world"
message_encoded = int(''.join(f'{ord(c):03d}' for c in message))

print(f"message text: {message}")
print(f"message_encoded text: {message_encoded}")

cipher_text = pow(message_encoded, e, n)
print(f"Cipher text: {cipher_text}")

decrypted_text = pow(cipher_text, d, n)
print(f"Decrypted text: {decrypted_text}")

# Convert decrypted text back to string
decrypted_message = ''.join(chr(int(str(decrypted_text)[i:i + 3])) for i in range(0, len(str(decrypted_text)), 3))
print(f"Decrypted message: {decrypted_message}")
