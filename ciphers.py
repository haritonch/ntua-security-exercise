#### auxiliary functions #################################

def repeat_to_length(string_to_expand, length):
    return (string_to_expand * (int(length/len(string_to_expand))+1))[:length]

def shift(x, n):
    if x == ' ':
        return ' '
    ascii = ord('A') + (ord('A') + ord(x) + n)%26
    return chr(ascii)

def permute(l, permutation):
    """ permutation example: [2, 0, 3, 1] (zero indexed) """
    ans = [None]*len(permutation)
    for i in range(len(permutation)):
        ans[permutation[i]] = l[i]
    return ans

def pad_with_c(message, modulo):
    ans = message
    while len(ans) % modulo != 0:
        ans += 'C'
    return ans

def xor(a, b):
    if len(a) != len(b):
        raise Exception('Different lengths on xor inputs')
    n = len(a)
    return [a[i]^b[i] for i in range(n)]

#### Ciphers ;) ########################################
""" The following ciphers are tested with capital letters """

class Caesar:
    def __init__(self, k=3):
        self.k = k

    def encrypt(self, plaintext):
        return ''.join(shift(c, self.k) for c in plaintext)

    def decrypt(self, ciphertext):
        return ''.join(shift(c, -self.k) for c in ciphertext)


class Substitution():
    def __init__(self, mapping):
        self.mapping = mapping
        self.inverse = {mapping[k]: k for k in mapping}

    def encrypt(self, message):
        return ''.join(self.mapping[c] for c in message)

    def decrypt(self, ciphertext):
        return ''.join(self.inverse[c] for c in ciphertext)


class Vigenere():
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        k = repeat_to_length(self.key, len(plaintext))
        return ''.join(
                [shift(plaintext[i], ord(k[i])-ord('A')) for i in range(len(plaintext))])

    def decrypt(self, ciphertext):
        k = repeat_to_length(self.key, len(ciphertext))
        return ''.join(
                [shift(ciphertext[i], ord('A')-ord(k[i])) for i in range(len(ciphertext))])


class RailFence:
    def __init__(self, nrows):
        if nrows < 2:
            raise Exception
        self.nrows = nrows

    def encrypt(self, message):
        nrows = self.nrows
        rows = [[] for i in range(nrows)]
        i, step = 0, 1
        for c in message:
            rows[i].append(c)
            if i%(nrows-1) == 0:
                step = -1
            if i == 0:
                step = 1
            i += step
        print(f'Rows:\n{rows}')
        return ''.join(list(map(lambda row: ''.join(row), rows)))

    def decrypt(self, ciphertext):
        count = [0] * self.nrows
        i, step = 0, 1
        for _ in ciphertext:
            count[i] += 1
            if i == 0:
                step = 1
            elif i % (self.nrows - 1) == 0:
                step = -1
            i += step
        ans, s = '', 0
        for i in range(self.nrows):
            ans += ciphertext[s:s+count[i]]
            s += count[i]
        return ans


class Permutation:
    def __init__(self, key):
        """ key example [2, 1, 3 ,0] """
        s = set(key)
        for i in range(len(key)):
            if i not in s:
                raise Exception
        self.plaintext_length = 0 # for padding removal on decryption
        self.ncols = len(key)
        self.permutation = key

    def encrypt(self, message):
        self.plaintext_length = len(message)
        ncols = self.ncols
        message = pad_with_c(message, self.ncols)
        cols = [[] for i in range(ncols)]
        for i, letter in enumerate(message):
            cols[i % ncols].append(letter)
        cols = permute(cols, self.permutation)
        ciphertext = ''.join(''.join(col) for col in cols)
        return ciphertext

    def decrypt(self, ciphertext):
        cols = []
        ncols, nrows = self.ncols, len(ciphertext) // len(self.permutation)
        for i in range(ncols):
            cols.append([letter for letter in ciphertext[i*nrows : (i+1)*nrows]])
        inverse = [0] * len(self.permutation)
        for i in range(len(self.permutation)):
            inverse[self.permutation[i]] = i
        cols = permute(cols, inverse)
        decrypted = ''
        for i in range(ncols*nrows):
            decrypted += cols[i%ncols][i // ncols]
        return decrypted[:self.plaintext_length]


if __name__ == '__main__':
    message = 'HELLO WORLD'
    key = 'KEY'
    print(f'Message: {message}')
    print(f'Key: {key}')
    cipher = Vigenere('MYKEY')
    ciphertext = cipher.encrypt(message)
    print(f'Ciphertext: {ciphertext}')
    dec = cipher.decrypt(ciphertext)
    print(f'Decrypted: {dec}')
