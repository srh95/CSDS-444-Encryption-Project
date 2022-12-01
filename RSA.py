import random

# First 100 prime numbers
first_primes_list = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                     31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 
                     73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 
                     127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 
                     179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 
                     233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 
                     283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
                     353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
                     419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
                     467, 479, 487, 491, 499, 503, 509, 521, 523, 541]
 
# Generate a random number N bits long
def nBitRandom(n):
    return random.randrange(2 ** (n-1) + 1, 2 ** n - 1)
 
# Makes sure that our prime candidate is not divisible by any of the first 100 primes
def getLowLevelPrime(n):
    # Generate a prime candidate not divisible by first primes
    while True:
        # get random number of n bits
        prime_candidate = nBitRandom(n)
 
        for divisor in first_primes_list:
            if prime_candidate % divisor == 0 and divisor ** 2 <= prime_candidate:
                break
        else: return prime_candidate
 
# Probabalistic primality test
# The more rounds, the more probable a number is prime
def isMillerRabinPassed(candidate, iterations):
    # Want to find numbers s and d so that candidate - 1 = (2^s)*d
    s = 0
    d = candidate - 1
    while d % 2 == 0:
        d >>= 1
        s += 1
    assert(2**s * d == candidate-1)
 
    # Seeing if we can find a witness that proves our candidate is composite
    # If a number fails to pass fermat's little theorem (a^(n-1) congruent to 1 mod n)
    # and fails to pass (a^((2^r)*d) congruent to -1 mod n) for some 0 <= r <= s
    # Then we know that the number is composite
    # Otherwise, it is probably prime! 
    def trialComposite(a):
        if pow(a, d, candidate) == 1:
            return False
        for i in range(s):
            if pow(a, 2**i * d, candidate) == candidate-1:
                return False
        return True
 
    # For the total number of iterations, run our helper method
    for i in range(iterations):
        # get a random number between 2 and our candidate to 
        a = random.randrange(2, candidate)
        if trialComposite(a):
            return False
    return True
 
def generate_prime():
    while True:
        # 1024 bits is the recommended length for a prime factor to use in RSA, but that is too computationally complex/slow for our purposes
        n = 10
        # Low level primality test
        prime_candidate = getLowLevelPrime(n)
        # High level primality test, 5 iterations
        if not isMillerRabinPassed(prime_candidate, 5):
            continue
        else:
            return prime_candidate

# Euclid's algorithm for finding GCD of two numbers
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# Euclid's extended algorithm for finding the multiplicative inverse of two numbers (modular)
# Requires the two numbers to be coprime
# we're solving (ax + by) = gcd(a, b), which should be 1 if they're coprime
# You can rewrite this as ax - 1 = (-y)m
# This is the same as saying ax is congruent to 1 mod m, so x is a modular multiplicative inverse of a 
def modInverse(a, b):
    m = b
    x = 1
    y = 0
    if (b == 1):
        return 0
    while (a > 1):
        # find whole number of times b goes into a
        q = a // b
        # set temp variable
        t = b
        # b becomes the remainder
        b = a % b
        # a becomes the original b
        a = t
        # set temp variable to y
        t = y
        # Update x and y
        y = x - q * y
        x = t
    # Make x positive
    if (x < 0):
        x = x + m
 
    return x

# Generates public and private key from 2 primes
def generate_keypair(p, q):
    n = p * q

    # Phi is the totient of n
    phi = (p-1) * (q-1)

    # Choose an integer e such that e and phi(n) are coprime
    e = random.randrange(1, phi)

    # Use Euclid's Algorithm to verify that e and phi(n) are comprime
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    # Use Extended Euclid's Algorithm to generate the private key
    d = modInverse(e, phi)
    
    # Return public and private keypair
    # Public key is (e, n) and private key is (d, n)
    return ((e, n), (d, n))

def encrypt(pk, plaintext):
    # Unpack the key into it's components
    key, n = pk
    # Convert each letter in the plaintext to numbers based on the character using a^b mod m
    cipher = [(ord(char) ** key) % n for char in plaintext]
    # Return the array of bytes
    return cipher

def decrypt(pk, ciphertext):
    # Unpack the key into its components
    key, n = pk
    # Generate the plaintext based on the ciphertext and key using a^b mod m
    plain = [chr((char ** key) % n) for char in ciphertext]
    # Return the array of bytes as a string
    return ''.join(plain)