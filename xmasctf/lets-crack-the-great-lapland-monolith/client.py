import argparse
import functools
import gmpy2
import re
import requests

if __name__ != '__main__':
    raise ImportError('Not for importing!')

# Arguments
parser = argparse.ArgumentParser()
grp = parser.add_mutually_exclusive_group(required=True)
grp.add_argument('--standard', help='Attack the "standard" monolith', action='store_true')
grp.add_argument('--greater',  help='Attack the "greater" monolith', action='store_true')
grp.add_argument('--target',   help='Attack a custom target. %g is replaced by the guess')
parser.add_argument('--guesses', help='The initial number of guesses to make. Increase to increase confidence', type=int, default=10)

args = parser.parse_args()
if args.standard:
    URL = 'http://199.247.6.180:12000/?guess={}'
elif args.greater:
    URL = 'http://199.247.6.180:12006/?guess={}'
else:
    URL = args.target

guesses = args.guesses
assert guesses >= 4, 'Need four or more guesses'

# Query methods
session = requests.Session()
def make_guess(number, s=session):
    r = s.get(URL.format(number))
    flag_match = re.search(r'X-MAS\{.*?\}', r.text)
    if flag_match:
        return flag_match.group(0)
    number_match = re.search(r'The Monolith desired:<br>(\d+)<br>', r.text)
    if not number_match:
        raise ValueError('Unexpected answer')
    return int(number_match.group(1))

# Our method is not 100% safe, so retry if we fail
while True:
    # Collect some numbers
    print('[*] Collecting numbers')
    numbers = [make_guess(0) for _ in range(guesses)]

    # Try to find the modulus m
    print('[*] Finding modulus')
    def matrix_det(at):
        a1 = numbers[at]     - numbers[0]
        b1 = numbers[at + 1] - numbers[1]
        a2 = numbers[at + 1] - numbers[0]
        b2 = numbers[at + 2] - numbers[1]
        return a1 * b2 - a2 * b1

    determinants = [matrix_det(i) for i in range(1, guesses - 2, 1)]
    m = int(functools.reduce(gmpy2.gcd, determinants))

    # Find LCG parameters a and k (s' = a * s + k mod m)
    # This is not entirely failsafe, but "good enough"
    # We solve
    #     a = (s' - s'') * modinv(s - s', m) mod m
    # Then,
    #     k = (s' - a * s) mod m
    print('[*] Trying to find remaining parameters')

    a = int(((numbers[1] - numbers[2]) * gmpy2.invert(numbers[0] - numbers[1], m)) % m)
    k = int((numbers[1] - numbers[0] * a) % m)

    print('[*] Trying parameters a = {}, k = {}, m = {}'.format(a, k, m))

    state = make_guess(0)
    success = False
    while True:
        state = (state * a + k) % m
        result = make_guess(state)
        if isinstance(result, str):
            print('[*] Found flag: {}'.format(result))
            success = True
            break
        elif result != state:
            print('[*] Mismatch: {} != {}'.format(state, result))
            success = False
            break
        else:
            print('[*] Guess {} was correct.'.format(state))
    if success:
        break
