def hex_string(obj):
    return ''.join('\\x{:02x}'.format(x) for x in obj).rstrip() if obj else ''
