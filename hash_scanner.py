import hashlib

def scanner(filebytes):

    dict = {}

    name_list = ['md5',
                'sha1',
                'sha224',
                'sha256',
                'sha384',
                'sha512'
                ]

    for obj in (name_list):
        temp_dict = {obj : eval('hashlib.{}(filebytes)'.format(obj)).hexdigest()}
        dict.update(temp_dict)

    print(dict)


if __name__ == '__main__':

    filebytes = b'This is a sample text'

    scanner(filebytes)
