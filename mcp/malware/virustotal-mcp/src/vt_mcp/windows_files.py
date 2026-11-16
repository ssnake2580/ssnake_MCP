# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Win32 handles for private submission receipts and immutable binary copies.

This adapter is loaded only on Windows. Receipt durability uses local NTFS,
CREATE_NEW, write-through and FlushFileBuffers, without replacing existing state.
"""

import ctypes as c
import os
import re
from contextlib import ExitStack, contextmanager
from ctypes import wintypes as w
from pathlib import Path


class WindowsFiles:
    def __init__(self):
        self.kernel = c.WinDLL("kernel32", use_last_error=True)
        self.advapi = c.WinDLL("advapi32", use_last_error=True)
        ptr = c.c_void_p
        signatures = [
            (self.kernel, "GetCurrentProcess", w.HANDLE, []),
            (self.kernel, "CloseHandle", w.BOOL, [w.HANDLE]),
            (self.kernel, "LocalFree", ptr, [ptr]),
            (self.kernel, "GetFileType", w.DWORD, [w.HANDLE]),
            (
                self.kernel,
                "CreateFileW",
                w.HANDLE,
                [w.LPCWSTR, w.DWORD, w.DWORD, ptr, w.DWORD, w.DWORD, w.HANDLE],
            ),
            (self.kernel, "CreateDirectoryW", w.BOOL, [w.LPCWSTR, ptr]),
            (self.kernel, "GetFileInformationByHandle", w.BOOL, [w.HANDLE, ptr]),
            (self.kernel, "FlushFileBuffers", w.BOOL, [w.HANDLE]),
            (
                self.kernel,
                "GetVolumeInformationByHandleW",
                w.BOOL,
                [w.HANDLE, w.LPWSTR, w.DWORD, ptr, ptr, ptr, w.LPWSTR, w.DWORD],
            ),
            (self.advapi, "OpenProcessToken", w.BOOL, [w.HANDLE, w.DWORD, ptr]),
            (self.advapi, "GetTokenInformation", w.BOOL, [w.HANDLE, c.c_int, ptr, w.DWORD, ptr]),
            (self.advapi, "ConvertSidToStringSidW", w.BOOL, [ptr, ptr]),
            (
                self.advapi,
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                w.BOOL,
                [w.LPCWSTR, w.DWORD, ptr, ptr],
            ),
            (
                self.advapi,
                "GetSecurityInfo",
                w.DWORD,
                [w.HANDLE, c.c_int, w.DWORD, ptr, ptr, ptr, ptr, ptr],
            ),
            (self.advapi, "GetSecurityDescriptorControl", w.BOOL, [ptr, ptr, ptr]),
            (self.advapi, "GetAce", w.BOOL, [ptr, w.DWORD, ptr]),
        ]
        for dll, name, result, arguments in signatures:
            function = getattr(dll, name)
            function.restype, function.argtypes = result, arguments

        class Attributes(c.Structure):
            _fields_ = [("length", w.DWORD), ("descriptor", ptr), ("inherit", w.BOOL)]

        class Information(c.Structure):
            _fields_ = [
                ("attributes", w.DWORD),
                ("created", w.FILETIME),
                ("accessed", w.FILETIME),
                ("written", w.FILETIME),
                ("volume", w.DWORD),
                ("size_high", w.DWORD),
                ("size_low", w.DWORD),
                ("links", w.DWORD),
                ("index_high", w.DWORD),
                ("index_low", w.DWORD),
            ]

        class ACL(c.Structure):
            _fields_ = [
                ("revision", w.BYTE),
                ("reserved", w.BYTE),
                ("size", w.WORD),
                ("count", w.WORD),
                ("reserved2", w.WORD),
            ]

        self.Attributes, self.Information, self.ACL = Attributes, Information, ACL
        token, size = w.HANDLE(), w.DWORD()
        self.require(
            self.advapi.OpenProcessToken(self.kernel.GetCurrentProcess(), 0x8, c.byref(token))
        )
        try:
            self.advapi.GetTokenInformation(token, 1, None, 0, c.byref(size))
            self.require(0 < size.value <= 16384)
            data = c.create_string_buffer(size.value)
            self.require(self.advapi.GetTokenInformation(token, 1, data, size, c.byref(size)))
            self.sid = self.sid_text(c.cast(data, c.POINTER(ptr))[0])
        finally:
            self.kernel.CloseHandle(token)

    @staticmethod
    def require(value):
        if not value:
            raise OSError("Private Windows submission storage could not be confirmed.")

    def sid_text(self, sid):
        text = w.LPWSTR()
        self.require(self.advapi.ConvertSidToStringSidW(sid, c.byref(text)))
        try:
            return text.value
        finally:
            self.kernel.LocalFree(text)

    @contextmanager
    def attributes(self):
        descriptor = c.c_void_p()
        self.require(
            self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                f"O:{self.sid}D:P(A;;FA;;;{self.sid})", 1, c.byref(descriptor), None
            )
        )
        try:
            yield self.Attributes(c.sizeof(self.Attributes), descriptor, False)
        finally:
            self.kernel.LocalFree(descriptor)

    @staticmethod
    def local_path(path):
        path = Path(path)
        if not path.is_absolute() or not re.fullmatch(r"[A-Za-z]:", path.drive):
            raise OSError("Use an absolute local Windows path.")
        if any(
            part in {".", ".."}
            or ":" in part
            or part.endswith((".", " "))
            or Path(part).is_reserved()
            for part in path.parts[1:]
        ):
            raise OSError(
                "Windows device paths, alternate streams and traversal are not supported."
            )
        return path

    @staticmethod
    def native(path):
        return "\\\\?\\" + str(path)

    def check(self, handle, *, directory=False, private=False):
        info = self.Information()
        self.require(self.kernel.GetFileInformationByHandle(handle, c.byref(info)))
        self.require(self.kernel.GetFileType(handle) == 1 and not info.attributes & 0x400)
        self.require(bool(info.attributes & 0x10) == directory)
        if private and not directory:
            self.require(info.links == 1)
        if not private:
            return
        owner, acl, descriptor = c.c_void_p(), c.c_void_p(), c.c_void_p()
        self.require(
            self.advapi.GetSecurityInfo(
                handle, 1, 0x1 | 0x4, c.byref(owner), None, c.byref(acl), None, c.byref(descriptor)
            )
            == 0
        )
        try:
            self.require(acl and self.sid_text(owner) == self.sid)
            control, revision = w.WORD(), w.DWORD()
            self.require(
                self.advapi.GetSecurityDescriptorControl(
                    descriptor, c.byref(control), c.byref(revision)
                )
            )
            self.require(control.value & 0x1000)  # Protected DACL, no inherited broad access.
            count = c.cast(acl, c.POINTER(self.ACL)).contents.count
            self.require(0 < count <= 4096)
            for index in range(count):
                ace = c.c_void_p()
                self.require(self.advapi.GetAce(acl, index, c.byref(ace)))
                header = (w.BYTE * 4).from_address(ace.value)
                if header[0] == 1 or header[1] & 0x08:  # Deny or inheritance-only.
                    continue
                self.require(header[0] == 0)
                self.require(self.sid_text(ace.value + 8) == self.sid)
        finally:
            self.kernel.LocalFree(descriptor)

    def ntfs(self, handle):
        filesystem, flags = c.create_unicode_buffer(32), w.DWORD()
        self.require(
            self.kernel.GetVolumeInformationByHandleW(
                handle, None, 0, None, None, c.byref(flags), filesystem, len(filesystem)
            )
        )
        self.require(filesystem.value == "NTFS" and flags.value & 0x8)

    @contextmanager
    def directory(self, path, *, create=False, private=False):
        if create:
            with self.attributes() as attributes:
                ok = self.kernel.CreateDirectoryW(self.native(path), c.byref(attributes))
                self.require(ok or c.get_last_error() == 183)
        # Keep this directory pinned while descendants are opened. No share-delete.
        handle = self.kernel.CreateFileW(
            self.native(path), 0x00020080, 1, None, 3, 0x02200000, None
        )
        self.require(handle != c.c_void_p(-1).value)
        try:
            self.check(handle, directory=True, private=private)
            yield handle
        finally:
            self.kernel.CloseHandle(handle)

    @contextmanager
    def parents(self, path, *, create=False, private_from=None):
        with ExitStack() as stack:
            current = Path(path.anchor)
            handle = stack.enter_context(self.directory(current))
            if create:
                self.ntfs(handle)
            for index, part in enumerate(path.parts[1:]):
                current = current / part
                handle = stack.enter_context(
                    self.directory(
                        current,
                        create=create,
                        private=private_from is not None and index >= private_from,
                    )
                )
            yield

    def open_file(self, path, *, create=False, private=False):
        import msvcrt

        access = 0x80000000 | (0x40000000 if create else 0)
        flags = 0x00200000 | (0x80000000 if create else 0)  # Reparse point / write-through.
        with self.attributes() as attributes:
            handle = self.kernel.CreateFileW(
                self.native(path), access, 1, c.byref(attributes), 1 if create else 3, flags, None
            )
            error = c.get_last_error()
        if handle == c.c_void_p(-1).value:
            if error in (80, 183):
                raise FileExistsError()
            raise OSError("Cannot safely open a Windows submission file.")
        try:
            self.check(handle, private=private)
            return msvcrt.open_osfhandle(
                handle, os.O_BINARY | (os.O_RDWR if create else os.O_RDONLY)
            )
        except BaseException:
            self.kernel.CloseHandle(handle)
            raise

    def flush(self, fd):
        import msvcrt

        self.require(self.kernel.FlushFileBuffers(msvcrt.get_osfhandle(fd)))


@contextmanager
def open_snapshot(path):
    files = WindowsFiles()
    source = files.local_path(Path(path).absolute())
    with files.parents(source.parent):
        fd = files.open_file(source)
        try:
            yield fd
        finally:
            os.close(fd)


def persist_reference(directory, service_key, identity_key, name, raw):
    files = WindowsFiles()
    root = files.local_path(directory)
    files.require(len(root.parts) >= 2)
    actor = root / service_key / identity_key
    with files.parents(actor, create=True, private_from=len(root.parts) - 2):
        try:
            fd = files.open_file(actor / name, create=True, private=True)
        except FileExistsError:
            fd = files.open_file(actor / name, private=True)
            try:
                files.require(os.fstat(fd).st_size == len(raw) and os.read(fd, len(raw) + 1) == raw)
            finally:
                os.close(fd)
            return False
        try:
            offset = 0
            while offset < len(raw):
                written = os.write(fd, raw[offset:])
                files.require(written > 0)
                offset += written
            # Never remove a failed/partial marker: uncertainty cannot permit a POST retry.
            files.flush(fd)
        finally:
            os.close(fd)
        return True
