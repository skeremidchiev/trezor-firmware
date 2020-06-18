import ustruct
from micropython import const

from trezor import io, loop, utils

if False:
    from typing import Any, Awaitable, Generator, NoReturn, Optional
    from trezorio import WireInterface

_REP_LEN = const(64)

_REP_MARKER = const(63)  # ord('?')
_REP_MAGIC = const(35)  # org('#')
_REP_INIT = ">BBBHL"  # marker, magic, magic, wire type, data length
_REP_INIT_DATA = const(9)  # offset of data in the initial report
_REP_CONT_DATA = const(1)  # offset of data in the continuation report

SESSION_ID = const(0)
INVALID_TYPE = const(-1)


class Reader:
    """
    Decoder for a wire codec over the HID (or UDP) layer.  Provides readable
    async-file-like interface.
    """

    def __init__(self, iface: WireInterface) -> None:
        self.iface = iface
        self.type = INVALID_TYPE
        self.size = 0
        self.ofs = 0
        self.data = bytes()

        self.wait = loop.wait(self.iface.iface_num() | io.POLL_READ)
        self._buf = None  # type: Optional[bytearray]
        self._nread = 0

    def __repr__(self) -> str:
        return "<Reader type: %s>" % self.type

    async def aopen(self) -> None:
        """
        Start reading a message by waiting for initial message report.  Because
        the first report contains the message header, `self.type` and
        `self.size` are initialized and available after `aopen()` returns.
        """
        while True:
            # wait for initial report
            report = await self.wait
            marker = report[0]
            if marker == _REP_MARKER:
                _, m1, m2, mtype, msize = ustruct.unpack(_REP_INIT, report)
                if m1 != _REP_MAGIC or m2 != _REP_MAGIC:
                    raise ValueError
                break

        # load received message header
        self.type = mtype
        self.size = msize
        self.data = report[_REP_INIT_DATA : _REP_INIT_DATA + msize]
        self.ofs = 0

    def areadinto(self, buf: bytearray) -> Awaitable[int]:
        """
        Read exactly `len(buf)` bytes into `buf`, waiting for additional
        reports, if needed.  Raises `EOFError` if end-of-message is encountered
        before the full read can be completed.
        """
        assert len(buf) > 0

        if self.size < len(buf):
            raise EOFError

        self._buf = buf
        self._nread = 0
        return self

    def send(self, arg: Any) -> Any:
        buf = self._buf
        assert buf is not None

        if arg is not None:
            # we have received result of self.wait
            marker = arg[0]
            if marker != _REP_MARKER:
                # wait again
                return self.wait

            # fill data from received message, reset offset
            self.data = arg[_REP_CONT_DATA : _REP_CONT_DATA + self.size]
            self.ofs = 0

        assert self._nread < len(buf)

        # copy as much as possible to target buffer
        nbytes = utils.memcpy(buf, self._nread, self.data, self.ofs, len(buf))
        self._nread += nbytes
        self.ofs += nbytes
        self.size -= nbytes

        if self._nread == len(buf):
            # we have all the data we need
            self._buf = None
            raise StopIteration(self._nread)

        # wait for new data
        return self.wait

    def throw(self, arg: Any) -> NoReturn:
        raise arg

    def close(self) -> None:
        pass

    def __iter__(self) -> Generator[Any, None, int]:
        return self  # type: ignore

    if False:

        def __await__(self) -> Generator[Any, None, int]:
            return self


class Writer:
    """
    Encoder for a wire codec over the HID (or UDP) layer.  Provides writable
    async-file-like interface.
    """

    def __init__(self, iface: WireInterface):
        self.iface = iface
        self.type = INVALID_TYPE
        self.size = 0
        self.ofs = 0
        self.data = bytearray(_REP_LEN)

    def setheader(self, mtype: int, msize: int) -> None:
        """
        Reset the writer state and load the message header with passed type and
        total message size.
        """
        self.type = mtype
        self.size = msize
        ustruct.pack_into(
            _REP_INIT, self.data, 0, _REP_MARKER, _REP_MAGIC, _REP_MAGIC, mtype, msize
        )
        self.ofs = _REP_INIT_DATA

    async def awrite(self, buf: bytes) -> int:
        """
        Encode and write every byte from `buf`.  Does not need to be called in
        case message has zero length.  Raises `EOFError` if the length of `buf`
        exceeds the remaining message length.
        """
        if self.size < len(buf):
            raise EOFError

        write = loop.wait(self.iface.iface_num() | io.POLL_WRITE)
        nwritten = 0
        while nwritten < len(buf):
            # copy as much as possible to report buffer
            nbytes = utils.memcpy(self.data, self.ofs, buf, nwritten, len(buf))
            nwritten += nbytes
            self.ofs += nbytes
            self.size -= nbytes

            if self.ofs == _REP_LEN:
                # we are at the end of the report, flush it
                while True:
                    await write
                    n = self.iface.write(self.data)
                    if n == len(self.data):
                        break
                self.ofs = _REP_CONT_DATA

        return nwritten

    async def aclose(self) -> None:
        """Flush and close the message transmission."""
        if self.ofs != _REP_CONT_DATA:
            # we didn't write anything or last write() wasn't report-aligned,
            # pad the final report and flush it
            while self.ofs < _REP_LEN:
                self.data[self.ofs] = 0x00
                self.ofs += 1

            write = loop.wait(self.iface.iface_num() | io.POLL_WRITE)
            while True:
                await write
                n = self.iface.write(self.data)
                if n == len(self.data):
                    break
