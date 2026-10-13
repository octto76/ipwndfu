"""Python compatibility checks; all USB traffic and external commands are mocked."""

import array
import binascii
import contextlib
import importlib
import io
import pathlib
import runpy
import struct
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import alloc8
import checkm8
import dfu
import dfuexec
import image3
import image3_24Kpwn
import libusbfinder
import limera1n
import nor
import recovery
import SHAtter
import steaks4uce
import usb._interop
import usb._objfinalizer
import usb.control
import usb.util
import usbexec
import utilities


class PythonCompatibilityTests(unittest.TestCase):
    def test_sources_compile_and_modules_import(self):
        paths = list(ROOT.glob('*.py')) + list((ROOT / 'usb').rglob('*.py'))
        paths += [ROOT / 'libusbfinder' / '__init__.py']
        with mock.patch.object(dfu, 'acquire_device', side_effect=AssertionError('Unexpected USB access')):
            for path in paths:
                with self.subTest(path=path):
                    compile(path.read_bytes(), str(path), 'exec')
                    name = '.'.join(path.relative_to(ROOT).with_suffix('').parts)
                    importlib.import_module(name.removesuffix('.__init__'))

    def test_command_line_help_and_invalid_arguments(self):
        for name in ('ipwndfu', 'ipwnrecovery', 'ibootpatcher'):
            for args, status in [(['--help'], 0), ([], 2), (['--invalid-option'], 2)]:
                with self.subTest(name=name, args=args):
                    result = subprocess.run([sys.executable, str(ROOT / name), *args],
                                            cwd=ROOT, capture_output=True, text=True, timeout=15)
                    self.assertEqual(result.returncode, status, result.stderr)
                    self.assertIn('usage', (result.stdout + result.stderr).lower())

    def test_cli_memory_dump_writes_raw_bytes(self):
        for serial, suffix in (('PWND:[checkm8]', b''), ('PWND:[limera1n]', b'\n')):
            with self.subTest(serial=serial):
                raw_output = io.BytesIO()
                output = io.TextIOWrapper(raw_output, encoding='utf-8')
                usb_device = types.SimpleNamespace(serial_number=serial)
                with mock.patch.object(sys, 'argv', ['ipwndfu', '--dump=0,2']), \
                     contextlib.redirect_stdout(output), \
                     mock.patch.object(dfu, 'acquire_device', return_value=usb_device), \
                     mock.patch.object(dfu, 'release_device'), \
                     mock.patch.object(usbexec, 'PwnedUSBDevice') as usb_factory, \
                     mock.patch.object(dfuexec, 'PwnedDFUDevice') as dfu_factory:
                    usb_factory.return_value.read_memory.return_value = b'\x80\xff'
                    dfu_factory.return_value.read_memory.return_value = b'\x80\xff'
                    runpy.run_path(str(ROOT / 'ipwndfu'), run_name='__main__')
                output.flush()
                self.assertEqual(raw_output.getvalue(), b'\x80\xff' + suffix)

    def test_cli_aes_prints_hex_without_bytes_repr(self):
        output = io.StringIO()
        usb_device = types.SimpleNamespace(serial_number='PWND:[checkm8]')
        with mock.patch.object(sys, 'argv', ['ipwndfu', '--decrypt-gid=' + '80' * 16]), \
             contextlib.redirect_stdout(output), \
             mock.patch.object(dfu, 'acquire_device', return_value=usb_device), \
             mock.patch.object(dfu, 'release_device'), \
             mock.patch.object(usbexec, 'PwnedUSBDevice') as factory:
            factory.return_value.aes.return_value = b'\xff' * 16
            runpy.run_path(str(ROOT / 'ipwndfu'), run_name='__main__')
        self.assertEqual(output.getvalue().splitlines()[-1], 'ff' * 16)
        self.assertEqual(factory.return_value.aes.call_args.args[0], b'\x80' * 16)

    def test_usb_arrays_use_binary_data(self):
        expected = b'\x00\x80\xff'
        for data in (expected, bytearray(expected), memoryview(expected), [0, 128, 255]):
            self.assertEqual(usb._interop.as_array(data).tobytes(), expected)
        original = array.array('B', expected)
        self.assertIs(usb._interop.as_array(original), original)
        self.assertEqual(usb._interop.as_array().tobytes(), b'')
        with self.assertRaises(TypeError):
            usb._interop.as_array('text')

    def test_usb_string_descriptor_decodes_unicode(self):
        text = 'Device \u00e9'
        encoded = text.encode('utf-16-le')
        descriptor = array.array('B', bytes([len(encoded) + 2, 3]) + encoded)
        device = types.SimpleNamespace(langids=(0x409,))
        with mock.patch.object(usb.control, 'get_descriptor', return_value=descriptor):
            self.assertEqual(usb.util.get_string(device, 1), text)

    def test_usb_finalization_runs_once(self):
        calls = []
        class Resource(usb._objfinalizer.AutoFinalizedObject):
            def _finalize_object(self):
                calls.append(True)
        resource = Resource()
        resource.finalize()
        resource.finalize()
        self.assertEqual(calls, [True])

    def test_dfu_read_chunks_return_bytes(self):
        device = mock.Mock()
        expected = b'\x80' * (dfu.MAX_PACKET_SIZE + 3)
        device.ctrl_transfer.side_effect = [array.array('B', expected[:dfu.MAX_PACKET_SIZE]),
                                            array.array('B', expected[dfu.MAX_PACKET_SIZE:])]
        self.assertEqual(dfu.get_data(device, len(expected)), expected)
        self.assertEqual(dfu.get_data(device, 0), b'')

    def test_dfu_write_chunks_remain_bytes(self):
        device = mock.Mock()
        device.ctrl_transfer.side_effect = lambda *args: len(args[4])
        data = b'\xff' * (dfu.MAX_PACKET_SIZE + 3)
        dfu.send_data(device, data)
        self.assertEqual(b''.join(call.args[4] for call in device.ctrl_transfer.call_args_list), data)

    def test_recovery_encodes_command_once(self):
        device = mock.Mock()
        recovery.send_command(device, 'setenv name \u00e9')
        self.assertEqual(device.ctrl_transfer.call_args.args[4], b'setenv name \xc3\xa9\x00')

    def test_exec_config_matches_binary_rom_info(self):
        config = usbexec.configs[0]
        info = b''.join(value.encode('ascii').ljust(size, b'\0')
                        for value, size in zip(config.info, (64, 64, 128)))
        self.assertTrue(config.match(info))
        self.assertFalse(config.match(b'\0' * 256))

    def test_usb_execute_accepts_large_integers_and_binary_tail(self):
        for arch, fmt in (('arm64', '<2Q'), ('armv7', '<I4xI')):
            for tail in (b'\xff', bytearray(b'\xff'), memoryview(b'\xff')):
                with self.subTest(arch=arch, tail=type(tail)):
                    device = object.__new__(usbexec.PwnedUSBDevice)
                    device.platform = types.SimpleNamespace(arch=arch)
                    device.command = mock.Mock(return_value=struct.pack('<8sQ', usbexec.DONE_MAGIC, 0) + b'\x80')
                    retval, received = device.execute(1, 0xF0000000, 2, tail)
                    self.assertEqual((retval, received), (0, b'\x80'))
                    self.assertEqual(device.command.call_args.args[0],
                                     usbexec.EXEC_MAGIC + struct.pack(fmt, 0xF0000000, 2) + b'\xff')

    def test_usb_command_reads_array_as_bytes(self):
        device = object.__new__(usbexec.PwnedUSBDevice)
        device.serial_number = 'test'
        usb_device = mock.Mock(serial_number='test')
        for length, reply in ((0, b'\x00'), (2, b'\x80\xff')):
            with self.subTest(length=length):
                usb_device.ctrl_transfer.return_value = array.array('B', reply)
                with mock.patch.object(dfu, 'acquire_device', return_value=usb_device), \
                     mock.patch.object(dfu, 'release_device'), mock.patch.object(dfu, 'send_data'):
                    self.assertEqual(device.command(b'\xff', length), reply[1:] if length == 0 else reply)

    def test_dfu_execute_rounds_receive_length_as_integer(self):
        device = object.__new__(dfuexec.PwnedDFUDevice)
        device.identifier = 'test'
        usb_device = types.SimpleNamespace(serial_number='test')
        for length in (0, 1, 0x7F8, 0x7F9, 0x1000):
            with self.subTest(length=length):
                reply = struct.pack('<2I', 0, 7) + b'\xff' * length
                with mock.patch.object(dfu, 'acquire_device', return_value=usb_device), \
                     mock.patch.object(dfu, 'release_device'), mock.patch.object(dfu, 'reset_counters'), \
                     mock.patch.object(dfu, 'send_data') as send, \
                     mock.patch.object(dfu, 'request_image_validation'), \
                     mock.patch.object(dfu, 'get_data', return_value=reply) as read, \
                     mock.patch.object(dfuexec.time, 'sleep'):
                    self.assertEqual(device.execute(b'\x80', length), (7, b'\xff' * length))
                    self.assertEqual(send.call_args.args[1], dfuexec.EXEC_MAGIC + b'\x80')
                    requested = read.call_args.args[1]
                    self.assertIsInstance(requested, int)
                    self.assertEqual(requested, ((8 + length + 0x7FF) // 0x800) * 0x800)

    def test_aes_hex_returns_text(self):
        device = object.__new__(dfuexec.PwnedDFUDevice)
        device.aes = mock.Mock(return_value=b'\xff' * 16)
        self.assertEqual(device.aes_hex('80' * 16, 17, 1), 'ff' * 16)
        device.aes.assert_called_once_with(b'\x80' * 16, 17, 1)

    def test_keybag_cache_is_binary(self):
        device = object.__new__(dfuexec.PwnedDFUDevice)
        device.config = types.SimpleNamespace(cpid='test')
        keybag, decrypted = b'\x80' * 48, b'\xff' * 48
        with tempfile.TemporaryDirectory() as directory:
            filename = str(pathlib.Path(directory) / 'keys')
            real_open = open
            def cache_open(path, mode):
                return real_open(filename, mode)
            with mock.patch('dfuexec.open', side_effect=cache_open), \
                 mock.patch.object(dfuexec, 'PwnedDFUDevice') as factory:
                factory.return_value.aes.return_value = decrypted
                self.assertEqual(device.decrypt_keybag(keybag), decrypted)
                self.assertEqual(device.decrypt_keybag(keybag), decrypted)
                factory.assert_called_once()
            self.assertEqual(pathlib.Path(filename).read_bytes(), keybag + decrypted)

    def test_image3_round_trip_and_binary_tags(self):
        tags = [(b'EPYT', 16, 4, b'blli'), (b'ATAD', 16, 4, b'\x00\x80\xff\x01')]
        binary = image3.Image3.createImage3FromTags(b'blli', tags)
        parsed = image3.Image3(binary)
        self.assertEqual(parsed.magic, b'3gmI')
        self.assertEqual(parsed.getPayload(), tags[1][3])
        self.assertEqual(parsed.newImage3(decrypted=False), binary)
        self.assertEqual(len(binary) % 64, 0)

    def test_image3_certificate_byte_indexing(self):
        certificate = b'\xff' * 10 + b'\0' * (3072 - 10)
        binary = image3.Image3.createImage3FromTags(b'blli', [(b'TREC', 3084, 3072, certificate)])
        parsed = image3.Image3(binary)
        parsed.shrink24KpwnCertificate()
        self.assertEqual(parsed.getTags(b'TREC')[0][3], b'\xff' * 10)

    def test_nor_round_trip(self):
        image = alloc8.empty_img3(64)
        header = struct.pack('<4s4I28x', b'2GMI', 64, 0, 8, 4)
        header += struct.pack('<I', binascii.crc32(header) & 0xFFFFFFFF)
        binary = header + b'\0' * (512 - len(header)) + image + b'\xff' * (nor.NOR_SIZE - 512 - len(image))
        parsed = nor.NorData(binary)
        self.assertEqual(parsed.images, [image])
        self.assertEqual(parsed.dump(), binary)

    def test_hex_dump_decodes_console_text(self):
        process = mock.Mock(returncode=0)
        process.communicate.return_value = (b'00000000: 80ff\n', b'')
        with mock.patch.object(utilities.subprocess, 'Popen', return_value=process):
            self.assertEqual(utilities.hex_dump(b'\x80\xff', 0), '00000000: 80ff\n')
        process.communicate.assert_called_once_with(input=b'\x80\xff')

    def test_openssl_arguments_are_text_and_result_is_bytes(self):
        process = mock.Mock(returncode=0)
        process.communicate.return_value = (b'\xff' * 16, b'')
        with mock.patch.object(utilities.subprocess, 'Popen', return_value=process) as launch:
            self.assertEqual(utilities.aes_decrypt(b'\x80' * 16, b'00' * 16, b'ff' * 16), b'\xff' * 16)
        self.assertTrue(all(isinstance(arg, str) for arg in launch.call_args.args[0]))

    def test_installed_libusb_fallback(self):
        with mock.patch.object(libusbfinder, 'libusb1_path', return_value=None), \
             mock.patch.object(libusbfinder.ctypes.util, 'find_library', return_value='libusb.so') as find:
            self.assertEqual(libusbfinder.find_library('usb-1.0'), 'libusb.so')
            find.assert_called_once_with('usb-1.0')

    def test_bundled_library_patches_are_bytes(self):
        for config in libusbfinder.configs:
            for offset, patch in config.dylib_patches:
                self.assertIsInstance(patch, bytes)

    def test_bundled_libusb_archives_extract_and_hash_correctly(self):
        with tempfile.TemporaryDirectory() as directory:
            path_format = str(pathlib.Path(directory) / '%s.dylib')
            for config in libusbfinder.configs:
                with self.subTest(version=config.version), \
                     mock.patch.object(libusbfinder.platform, 'mac_ver', return_value=(config.version + '.6', (), '')), \
                     mock.patch.object(libusbfinder, 'DYLIB_PATH_FORMAT', path_format):
                    path = libusbfinder.libusb1_path_internal()
                    self.assertEqual(path, path_format % config.bottle)
                    self.assertTrue(pathlib.Path(path).is_file())
                    self.assertEqual(libusbfinder.libusb1_path_internal(), path)

    def test_alloc8_binary_images_and_padding(self):
        original = types.SimpleNamespace(parts=[b'', b'\0' * 460], images=[], block_size=64)
        with contextlib.chdir(ROOT):
            for version in ('359.3', '359.3.2'):
                with self.subTest(version=version):
                    modified = alloc8.exploit(original, version)
                    self.assertEqual(len(modified.images), 715)
                    self.assertEqual(len(modified.parts[1]), 460)
                    self.assertTrue(all(isinstance(image, bytes) for image in modified.images))
                    restored = alloc8.remove_exploit(modified)
                    self.assertEqual(restored.images, [])
                    self.assertEqual(restored.parts[1], b'\0' * 460)

    def test_24kpwn_image_serialization(self):
        binary = image3.Image3.createImage3FromTags(b'blli', [
            (b'ATAD', 16, 4, b'\x00' * 4), (b'HSHS', 76, 64, b'\xff' * 64)])
        with contextlib.chdir(ROOT):
            result = image3_24Kpwn.exploit(binary, b'\x80' * 0x10000)
        self.assertEqual(len(result), 0x24200)
        self.assertEqual(result[:4], b'3gmI')

    def test_payload_builders_return_bytes(self):
        with contextlib.chdir(ROOT):
            for config in checkm8.all_exploit_configs():
                with self.subTest(cpid=config.cpid):
                    payload = checkm8.payload(config.cpid)
                    self.assertIsInstance(payload, bytes)
                    self.assertTrue(payload)
            for config in limera1n.configs:
                self.assertIsInstance(limera1n.generate_payload(config.constants, config.exploit_lr), bytes)
            for config in steaks4uce.configs:
                self.assertIsInstance(steaks4uce.generate_shellcode(config.constants), bytes)
            self.assertIsInstance(SHAtter.generate_payload(), bytes)

    def test_arm64_branch_uses_integer_offsets(self):
        patcher = runpy.run_path(str(ROOT / 'ibootpatcher'))
        for branch in (checkm8.asm_arm64_branch, patcher['arm64_branch_instruction']):
            self.assertEqual(branch(0x100, 0x108), struct.pack('<I', 0x14000002))
            self.assertEqual(branch(0x108, 0x100), struct.pack('<I', 0x17FFFFFE))

    def test_iboot_patches_binary_instructions(self):
        patcher = runpy.run_path(str(ROOT / 'ibootpatcher'))
        with contextlib.redirect_stdout(io.StringIO()):
            result = patcher['apply_generic_el3_patches'](patcher['MSR_VBAR_EL3_X10'] + b'\xff' * 4)
        self.assertEqual(result, patcher['MSR_VBAR_EL1_X10'] + b'\xff' * 4)


if __name__ == '__main__':
    unittest.main()
