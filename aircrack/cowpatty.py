import shlex
import subprocess


class Cowpatty:
    @classmethod
    def contains_valid_handshake(cls, cap_file: str) -> bool:
        valid_str = 'Collected all necessary data to mount crack against WPA2/PSK passphrase.'
        with subprocess.Popen(shlex.split(
            f'cowpatty -c -r {cap_file}'
        ), stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE) as process:
            return valid_str in process.stdout.read().decode()
