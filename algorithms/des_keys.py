# DES Key Schedule (PC-1, PC-2, Shifts)
PC1 = [57,49,41,33,25,17,9,
       1,58,50,42,34,26,18,
       10,2,59,51,43,35,27,
       19,11,3,60,52,44,36,
       63,55,47,39,31,23,15,
       7,62,54,46,38,30,22,
       14,6,61,53,45,37,29,
       21,13,5,28,20,12,4]

PC2 = [14,17,11,24,1,5,3,28,
       15,6,21,10,23,19,12,4,
       26,8,16,7,27,20,13,2,
       41,52,31,37,47,55,30,40,
       51,45,33,48,44,49,39,56,
       34,53,46,42,50,36,29,32]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

def permute(block, table):
    return ''.join([block[i-1] for i in table])

def left_shift(bits, n):
    return bits[n:] + bits[:n]

def generate_keys(key):
    """key: 64-bit binary string"""
    # Apply PC-1
    permuted = permute(key, PC1)
    C, D = permuted[:28], permuted[28:]
    round_keys = []

    for shift in SHIFTS:
        C, D = left_shift(C, shift), left_shift(D, shift)
        combined = C + D
        K = permute(combined, PC2)
        round_keys.append(K)
    return round_keys
