
sudoku =[7,6,0,3,8,5,1,0,9,
                         8,4,9,1,2,6,7,5,3,
                         1,0,3,4,7,9,8,2,6,
                         6,7,1,8,9,2,4,3,5,
                         9,3,4,5,1,7,0,6,8,
                         0,2,8,6,4,3,9,1,7,
                         4,0,6,0,3,1,5,9,2,
                         3,9,7,2,5,4,6,0,1,
                         2,1,5,0,6,0,3,7,4]

entropy = [7777853, 6222378, 3546017, 4445136, 7780945, 3462586, 3111820, 2405140, 3624625, 6968615, 3176867, 3710589, 7702269, 3192178, 649731, 7800749, 6017677, 6189630, 1975056, 2694116, 3038398, 1663188, 6543815, 4176440, 1696171, 2471993, 1030495, 1229599, 6638142, 7858312, 5114362, 6754064, 5507984, 2092153, 4221209, 3125287, 3738908, 4746424, 7514587, 3209489, 5982099, 5252558, 2931922, 7955762, 1710208, 296028, 3099603, 1923308, 1816384, 7460259, 4688990, 3698787, 8063985, 2904281, 2387354, 1096597, 7513812, 6846883, 1839444, 3299084, 631091, 8290017, 7160748, 1179054, 2243030, 1709908, 1675438, 240870, 5979594, 213499, 2931947, 6795798, 3096344, 6255267, 3628236, 1266072, 416109, 145294, 3209749, 7941896, 4764432]

def encrypt(value, k):
    return (value) - entropy[80 - k]

def decrypt(puzzle, k):
    return (puzzle)[k] + entropy[80 - k]

for i, val in enumerate(sudoku):
    sudoku[i] = encrypt(val, i)
    # print(decrypt(sudoku, i))
    assert decrypt(sudoku, i) == val

print(sudoku)

password = list(map(lambda x: x - 1, [2, 4, 5, 2, 5, 8, 7, 8, 9, 8]))

def encrypt_pass(val, index):
    return val + entropy[46 - password[index % len(password)]]

def decrypt_pass(val, index):
    return val - entropy[46 - password[index % len(password)]]



print(password)

flag = 'uiuctf{which_shows_that_rop_is_turing_complete_QED}'

encrypted = []
for i, val in enumerate(flag):
    encrypted.append(encrypt_pass(ord(val), i))

print(encrypted)

for i, val in enumerate(encrypted):
    print(chr(decrypt_pass(val, i)))

print(len(flag))