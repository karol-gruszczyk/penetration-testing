with open('/usr/share/dict/words', 'r') as file:
    WORDS = {line.replace("'", '').lower().strip() for line in file.readlines()}



class PasswordGenerator:
    def __init__(self):
        pass


if __name__ == '__main__':
    print('rapid' in WORDS)
    print('advancement' in WORDS)
