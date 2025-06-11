# Raw Gadget-based Facedancer backend.
#
# See https://github.com/xairy/raw-gadget for details about Raw Gadget.
#
# Authors:
#   Andrey Konovalov <andreyknvl@gmail.com>
#   Kirill Zhirovsky <me@kirill9617.win>
#   Devin Bayer <dev@doubly.so>

from __future__ import annotations

from dataclasses import dataclass
import errno
import fcntl
import os
from threading import Thread
from signal import signal, SIGUSR1, pthread_kill

from queue import Queue

from construct import (
    Bit,
    BitStruct,
    BitsSwapped,
    Bytes,
    Enum,
    Int16ul,
    Int16un,
    Int32un,
    Int8ul,
    Int8un,
    Padding,
    PaddedString,
    Struct,
    this,
)

from facedancer.device import USBDevice
from facedancer.endpoint import USBEndpoint
from facedancer.request import USBControlRequest
from facedancer.types import (
    DeviceSpeed,
    USBDirection,
    USBRequestRecipient,
    USBStandardRequests,
)
from facedancer.core import FacedancerApp

from ..logging import log
from .base import FacedancerBackend


class RawGadgetBackend(FacedancerApp, FacedancerBackend):
    app_name = "Raw Gadget"

    device: RawGadget
    connected_device: USBDevice
    queue: Queue
    eps: dict[int, EndpointHandler]

    def __init__(
        self,
        device: RawGadget | None = None,
        verbose: int = 0,
        quirks=None,
    ):
        """
        Initializes the backend.

        Args:
            device  : The device that will act as our UDC.          (Optional)
            verbose : The verbosity level of the given application. (Optional)
            quirks  : List of USB platform quirks.                  (Optional)
        """
        super().__init__(device or RawGadget(verbose), verbose)

        self.queue = Queue(100)
        self.eps = {}
        self.eps_info = None
        self.connected_device = None
        self.is_configured = False
        self.is_suspended = False

        self.device.open()

    @classmethod
    def appropriate_for_environment(cls, backend_name: str | None) -> bool:
        """
        Determines if the current environment seems appropriate
        for using this backend.

        Args:
            backend_name : Backend name being requested. (Optional)
        """
        if backend_name and backend_name != "rawgadget":
            return False

        try:
            rg = open("/dev/raw-gadget")
            rg.close()
            return True
        except ImportError:
            log.info("Skipping Raw Gadget, as could not open /dev/raw-gadget .")
            return False
        except Exception:
            log.exception("Raw Gadget check fail", exc_info=True, stack_info=True)
            return False

    def get_version(self):
        """
        Returns information about the active Facedancer version.
        """
        raise NotImplementedError

    def connect(
        self,
        usb_device: USBDevice,
        max_packet_size_ep0: int = 64,
        device_speed: DeviceSpeed = DeviceSpeed.FULL,
    ):
        """
        Prepares backend to connect to the target host and emulate
        a given device.

        Args:
            usb_device : The USBDevice object that represents the emulated device.
            max_packet_size_ep0 : Max packet size for control endpoint.
            device_speed : Requested usb speed for the Facedancer board.
        """
        if self.verbose > 0:
            log.info("connecting device: %s (%r)", usb_device.name, device_speed)

        self.connected_device = usb_device
        self.device.run(speed=device_speed)
        self.control = ControlHandler(self)

    def disconnect(self):
        """Disconnects Facedancer from the target host."""
        assert self.connected_device
        self._disable()
        self.control.stop()
        self.device.close()

        if self.verbose > 0:
            log.info("disconnected device: %s", self.connected_device.name)

        self.connected_device = None

    def reset(self):
        """Does nothing since gadgets cannot initiate device-side resets."""
        log.info("ignoring reset request")

    def set_address(self, address: int, defer: bool = False):
        """
        Sets the device address of the Facedancer. Usually only used during
        initial configuration.

        Args:
            address : The address the Facedancer should assume.
            defer   : True iff the set_address request should wait for an active transaction to
                      finish.
        """
        # Raw Gadget backend cannot receive a SET_ADDRESS request, as this
        # request is handled by the UDC driver.
        raise NotImplementedError

    def configured(self, configuration):
        """
        Callback that's issued when a USBDevice is configured, e.g. by the
        SET_CONFIGURATION request. Allows us to apply the new configuration.

        Args:
            configuration : The USBConfiguration object applied by the SET_CONFIG request.
        """
        log.info("applying configuration")
        self.validate_configuration(configuration)

        self._disable()

        self.device.vbus_draw(configuration.max_power // 2)
        self.device.configure()

        self.configuration = configuration
        self.is_configured = True

        self._enable()

    def read_from_endpoint(self, endpoint_number: int) -> bytes:
        """
        Reads a block of data from the given endpoint.

        Args:
            endpoint_number : The number of the OUT endpoint on which data is to be rx'd.
        """
        raise NotImplementedError(
            "read_from_endpoint happens automatically in background"
        )

    def send_on_endpoint(
        self, endpoint_number: int, data: bytes, blocking: bool = True
    ):
        """
        Sends a collection of USB data on a given endpoint.

        Args:
            endpoint_number : The number of the IN endpoint on which data should be sent.
            data : The data to be sent.
            blocking : This must always be true.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError(f" {type(data)=}, must be bytes")

        if self.verbose > 4:
            log.debug(
                f"send ep{endpoint_number} {self.last_control_direction.name} len={len(data)} {blocking=}"
            )

        if endpoint_number == 0:
            if self.verbose > 2:
                log.info(
                    f"send ep0 {self.last_control_direction.name} {data.hex(' ', -2)}"
                )
            self.control.send(data, self.last_control_direction)
        else:
            handler = self.eps[endpoint_number]
            assert isinstance(handler, EndpointInHandler)
            handler.send(data)

    def ack_status_stage(
        self,
        direction: USBDirection = USBDirection.OUT,
        endpoint_number: int = 0,
        blocking: bool = False,
    ):
        """
        Handles the status stage of a correctly completed control request,
        by priming the appropriate endpoint to handle the status phase.

        Args:
            direction : Determines if we're ACK'ing an IN or OUT vendor request.
                       (This should match the direction of the DATA stage.)
            endpoint_number : The endpoint number on which the control request
                              occurred.
            blocking : Only True is supported.
        """
        acked = self.last_control_acked
        if self.verbose > 4:
            log.info(f"ack {acked=} {direction.name} {endpoint_number=} {blocking=}")
        if acked:
            return

        if endpoint_number != 0:
            raise NotImplementedError()

        self.control.send(b"", direction)

    def stall_endpoint(
        self, endpoint_number: int, direction: USBDirection = USBDirection.OUT
    ):
        """
        Stalls the provided endpoint, as defined in the USB spec.

        Args:
            endpoint_number : The number of the endpoint to be stalled.
        """
        if self.verbose > 0:
            log.info(f"stall endpoint={endpoint_number} {direction.name}")

        if endpoint_number == 0:
            self.device.ep0_stall()
        else:
            # Raw Gadget does support stalling non-control endpoints, but none
            # of the Facedancer examples do this. Thus, testing this feature is
            # hard, so leave this as not implemented.
            raise NotImplementedError()

    def service_irqs(self):
        """
        Core event loop - reacts to events from the host via the rawgadget API.
        """
        event = self.queue.get()
        match event:
            case RawGadgetEvent(kind, data):
                self._handle_raw_gadget_event(kind, data)
            case EpReadEvent(ep, handler, data):
                if handler.stopped:
                    log.debug(f"discarding event {event} from stopped handler")
                    return
                self.connected_device.handle_data_received(ep, data)
            case _:
                assert False

    ##############################################################################
    # Internal functions

    def _handle_raw_gadget_event(self, kind, data):
        if self.verbose > 4:
            log.debug(f"recv event {kind} len={len(data)}")

        match kind:
            case usb_raw_event_type.USB_RAW_EVENT_CONNECT:
                # UDC endpoint information is only obtained for reference:
                # this backend does use it in any way. In the future, this
                # backend can be extended to validate UDC endpoints
                # capabilities against the device endpoint descriptors.
                self.eps_info = self.device.eps_info()
            case usb_raw_event_type.USB_RAW_EVENT_CONTROL:
                self._recv_control(data)
            case usb_raw_event_type.USB_RAW_EVENT_DISCONNECT:
                # For an unclear reason, some UDC drivers issue a disconnect
                # event when the device is being reconfigured. Thus, treat
                # disconnect as reset.
                log.info("gadget disable")
                self._reset()
            case usb_raw_event_type.USB_RAW_EVENT_SUSPEND:
                log.info("gadget suspended")
                self.is_suspended = True
            case usb_raw_event_type.USB_RAW_EVENT_RESET:
                log.info("gadget reset")
                self._reset()
            case usb_raw_event_type.USB_RAW_EVENT_RESUME:
                self.is_suspended = False
                log.info("gadget resumed")
            case _:
                # Raw Gadget might be extended and start reporting other kinds
                # of events. Instead of ignoring these events, raise an
                # exception to hint that this backend must be extended as well.
                raise NotImplementedError()

    def _recv_control(self, data: bytes):
        req: USBControlRequest = self.connected_device.create_request(data)

        if self.verbose > 2:
            log.debug(f"recv control {req}")

        self.last_control_direction = USBDirection(req.get_direction())
        self.last_control_acked = False

        if req.direction == USBDirection.OUT and req.length != 0:
            rv, ep_request = self.device.ep0_read(bytearray(req.length))
            assert ep_request and rv == req.length
            req.data = bytes(ep_request.data)
            self.last_control_acked = True
            if self.verbose > 3:
                log.debug(f"  data {data.hex(' ', -2)}")

        reenable = False
        if (
            req.get_recipient() == USBRequestRecipient.INTERFACE
            and req.request == USBStandardRequests.SET_INTERFACE
        ):
            log.info(f"gadget set interface {req.index} alt {req.value}")
            reenable = True

        # TODO - only disable handlers for the target interface
        if reenable:
            self._disable()

        self.connected_device.handle_request(req)

        if reenable:
            self._enable()

    def _reset(self):
        self.is_configured = False
        self._disable()

        if self.connected_device:
            self.connected_device.handle_bus_reset()

    def _enable(self):
        if not self.is_configured:
            return

        for interface in self.configuration.get_interfaces():
            for ep in interface.get_endpoints():
                if ep.direction == USBDirection.IN:
                    self.eps[ep.number] = EndpointInHandler(ep, self)
                else:
                    self.eps[ep.number] = EndpointOutHandler(ep, self)

    def _disable(self):
        for ep in self.eps.values():
            ep.stop()

        self.eps = {}


class TrailingBytes(Bytes):
    def _sizeof(self, context, path):
        return 0


usb_endpoint_descriptor = Struct(
    "bLength" / Int8ul,
    "bDescriptorType" / Int8ul,
    "bEndpointAddress" / Int8ul,
    "bmAttributes" / Int8ul,
    "wMaxPacketSize" / Int16ul,
    "bInternal" / Int8ul,
    "bRefresh" / Int8ul,
    "bSynchAddress" / Int8ul,
)

usb_ctrlrequest = Struct(
    "bRequestType" / Int8ul,
    "bRequest" / Int8ul,
    "wValue" / Int16ul,
    "wIndex" / Int16ul,
    "wLength" / Int16ul,
)

UDC_NAME_LENGTH_MAX = 128

usb_raw_init = Struct(
    "driver_name" / PaddedString(UDC_NAME_LENGTH_MAX, "ascii"),
    "device_name" / PaddedString(UDC_NAME_LENGTH_MAX, "ascii"),
    "speed" / Int8un,
)

usb_raw_event_type = Enum(
    Int32un,
    USB_RAW_EVENT_INVALID=0,
    USB_RAW_EVENT_CONNECT=1,
    USB_RAW_EVENT_CONTROL=2,
    USB_RAW_EVENT_SUSPEND=3,
    USB_RAW_EVENT_RESUME=4,
    USB_RAW_EVENT_RESET=5,
    USB_RAW_EVENT_DISCONNECT=6,
)

usb_raw_event = Struct(
    "kind" / usb_raw_event_type, "length" / Int32un, "data" / TrailingBytes(this.length)
)

usb_raw_ep_io = Struct(
    "ep" / Int16un,
    "flags" / Int16un,
    "length" / Int32un,
    "data" / TrailingBytes(this.length),
)

usb_raw_ep_caps = BitsSwapped(
    BitStruct(
        "type_control" / Bit,
        "type_iso" / Bit,
        "type_bulk" / Bit,
        "type_int" / Bit,
        "dir_in" / Bit,
        "dir_out" / Bit,
        Padding(26),
    )
)

usb_raw_ep_limits = Struct(
    "maxpacket_limit" / Int16un, "max_streams" / Int16un, "reserved" / Int32un
)

USB_RAW_EPS_NUM_MAX = 30
USB_RAW_EP_NAME_MAX = 16

usb_raw_ep_info = Struct(
    "name" / PaddedString(USB_RAW_EP_NAME_MAX, "ascii"),
    "addr" / Int32un,
    "caps" / usb_raw_ep_caps,
    "limits" / usb_raw_ep_limits,
)

usb_raw_eps_info = Struct("eps" / usb_raw_ep_info[USB_RAW_EPS_NUM_MAX])


class IOCTLRequest:
    IOC_NONE = 0
    IOC_WRITE = 1
    IOC_READ = 2

    IOC_NRBITS = 8
    IOC_TYPEBITS = 8
    IOC_SIZEBITS = 14
    IOC_DIRBITS = 2

    IOC_NRSHIFT = 0
    IOC_TYPESHIFT = IOC_NRSHIFT + IOC_NRBITS
    IOC_SIZESHIFT = IOC_TYPESHIFT + IOC_TYPEBITS
    IOC_DIRSHIFT = IOC_SIZESHIFT + IOC_SIZEBITS

    @staticmethod
    def IOC(dir, typ, nr, size):
        if size is None:
            size = 0
        else:
            size = size.sizeof()
        if isinstance(typ, str):
            typ = ord(typ[0])
        if isinstance(dir, str):
            dir = {
                "": IOCTLRequest.IOC_NONE,
                "R": IOCTLRequest.IOC_READ,
                "W": IOCTLRequest.IOC_WRITE,
                "WR": IOCTLRequest.IOC_WRITE | IOCTLRequest.IOC_READ,
            }[dir]
        return (
            dir << IOCTLRequest.IOC_DIRSHIFT
            | typ << IOCTLRequest.IOC_TYPESHIFT
            | nr << IOCTLRequest.IOC_NRSHIFT
            | size << IOCTLRequest.IOC_SIZESHIFT
        )

    @staticmethod
    def ioc(dir, typ, nr, size):
        def fn(fd, arg=0):
            req = IOCTLRequest.IOC(dir, typ, nr, size)
            if isinstance(arg, bytes):
                arg = bytearray(arg)
            try:
                rv = fcntl.ioctl(fd, req, arg, True)
            except OSError as e:
                if e.errno == errno.ETIME:
                    raise TimeoutError
                raise
            return rv, arg

        return fn


class RawGadgetRequests(IOCTLRequest):
    USB_RAW_IOCTL_INIT = IOCTLRequest.ioc("W", "U", 0, usb_raw_init)
    USB_RAW_IOCTL_RUN = IOCTLRequest.ioc("", "U", 1, None)
    USB_RAW_IOCTL_EVENT_FETCH = IOCTLRequest.ioc("R", "U", 2, usb_raw_event)
    USB_RAW_IOCTL_EP0_WRITE = IOCTLRequest.ioc("W", "U", 3, usb_raw_ep_io)
    USB_RAW_IOCTL_EP0_READ = IOCTLRequest.ioc("WR", "U", 4, usb_raw_ep_io)
    USB_RAW_IOCTL_EP_ENABLE = IOCTLRequest.ioc("W", "U", 5, usb_endpoint_descriptor)
    USB_RAW_IOCTL_EP_DISABLE = IOCTLRequest.ioc("W", "U", 6, Int32un)
    USB_RAW_IOCTL_EP_WRITE = IOCTLRequest.ioc("W", "U", 7, usb_raw_ep_io)
    USB_RAW_IOCTL_EP_READ = IOCTLRequest.ioc("WR", "U", 8, usb_raw_ep_io)
    USB_RAW_IOCTL_CONFIGURE = IOCTLRequest.ioc("", "U", 9, None)
    USB_RAW_IOCTL_VBUS_DRAW = IOCTLRequest.ioc("W", "U", 10, Int32un)
    USB_RAW_IOCTL_EPS_INFO = IOCTLRequest.ioc("R", "U", 11, usb_raw_eps_info)
    USB_RAW_IOCTL_EP0_STALL = IOCTLRequest.ioc("", "U", 12, None)
    USB_RAW_IOCTL_EP_SET_HALT = IOCTLRequest.ioc("W", "U", 13, Int32un)
    USB_RAW_IOCTL_EP_CLEAR_HALT = IOCTLRequest.ioc("W", "U", 14, Int32un)
    USB_RAW_IOCTL_EP_SET_WEDGE = IOCTLRequest.ioc("W", "U", 15, Int32un)


class RawGadget:
    def __init__(self, verbose=1):
        self.udc_driver = os.environ.get("RG_UDC_DRIVER", "dummy_udc").lower()
        self.udc_device = os.environ.get("RG_UDC_DEVICE", "dummy_udc.0").lower()

        self.fd = None
        self.last_ep_addr = 0
        self.verbose = verbose

    def open(self):
        self.fd = open("/dev/raw-gadget", "bw")

    def close(self):
        assert self.fd is not None
        self.fd.close()
        self.fd = None

    def run(self, speed: DeviceSpeed):
        if override := os.environ.get("RG_USB_SPEED"):
            log.info(f"Overriding device speed with RG_USB_SPEED={override}")
            speed = DeviceSpeed(override)

        arg = usb_raw_init.build(
            {
                "driver_name": self.udc_driver,
                "device_name": self.udc_device,
                "speed": speed,
            }
        )
        RawGadgetRequests.USB_RAW_IOCTL_INIT(self.fd, arg)
        RawGadgetRequests.USB_RAW_IOCTL_RUN(self.fd)

    def event_fetch(self, data):
        arg = usb_raw_event.build({"kind": 0, "length": len(data), "data": data})
        try:
            _, data = RawGadgetRequests.USB_RAW_IOCTL_EVENT_FETCH(self.fd, arg)
        except TimeoutError:
            return None

        raw = usb_raw_event.parse(data)
        return RawGadgetEvent(raw.kind, raw.data)

    def ep0_write(self, data, flags=0):
        arg = usb_raw_ep_io.build(
            {"ep": 0, "flags": flags, "length": len(data), "data": data}
        )
        try:
            RawGadgetRequests.USB_RAW_IOCTL_EP0_WRITE(self.fd, arg)
        except TimeoutError:
            pass

    def ep0_read(self, data, flags=0):
        arg = usb_raw_ep_io.build(
            {"ep": 0, "flags": flags, "length": len(data), "data": data}
        )
        try:
            rv, data = RawGadgetRequests.USB_RAW_IOCTL_EP0_READ(self.fd, arg)
        except TimeoutError:
            return None, None

        return rv, usb_raw_ep_io.parse(data)

    def ep_enable(self, ep_desc):
        handle, _ = RawGadgetRequests.USB_RAW_IOCTL_EP_ENABLE(self.fd, ep_desc)
        log.info(f"ep_enable: {handle=}")
        return handle

    def ep_disable(self, handle: int):
        RawGadgetRequests.USB_RAW_IOCTL_EP_DISABLE(self.fd, handle)
        log.info(f"ep_disable: {handle=}")

    def ep_write(self, handle, data, flags=0):
        arg = usb_raw_ep_io.build(
            {"ep": handle, "flags": flags, "length": len(data), "data": data}
        )
        try:
            rv, _ = RawGadgetRequests.USB_RAW_IOCTL_EP_WRITE(self.fd, arg)
        except TimeoutError:
            log.warning(f"Timeout: ep_write {handle} {data.hex()}")
            return

        if rv != len(data):
            log.warning(f"ep_write {handle=} length={len(data)} {rv=}")

        elif self.verbose > 4:
            log.debug(f"ep_write: {handle=} {flags=} {rv=}")

    def ep_read(self, handle, length, flags=0):
        arg = usb_raw_ep_io.build(
            {"ep": handle, "flags": flags, "length": length, "data": bytes(length)}
        )
        try:
            rv, arg = RawGadgetRequests.USB_RAW_IOCTL_EP_READ(self.fd, arg)
        except TimeoutError:
            if self.verbose > 4:
                log.debug(f"Timeout: ep_read {handle=}")
            return None

        if self.verbose > 3:
            log.debug(f"ep_read: {handle=} {flags=} {length=} {rv=}")

        return usb_raw_ep_io.parse(arg).data[:rv]

    def configure(self):
        RawGadgetRequests.USB_RAW_IOCTL_CONFIGURE(self.fd)

    def vbus_draw(self, power):
        RawGadgetRequests.USB_RAW_IOCTL_VBUS_DRAW(self.fd, power)

    def eps_info(self):
        eps_info = bytes(usb_raw_eps_info.sizeof())
        num, resp = RawGadgetRequests.USB_RAW_IOCTL_EPS_INFO(self.fd, eps_info)
        return usb_raw_eps_info.parse(resp)

    def ep0_stall(self):
        RawGadgetRequests.USB_RAW_IOCTL_EP0_STALL(self.fd)


@dataclass
class RawGadgetEvent:
    kind: int
    data: bytes


@dataclass
class EpReadEvent:
    ep: USBEndpoint
    handler: EndpointHandler
    data: bytes


def _ignore(signum, _frame):
    log.debug(f"ignoring {signum}")


class ControlHandler:
    """Send and receive raw gadget control events that can block."""

    def __init__(self, backend):
        self.backend = backend
        self.stopped = False

        # use SIGUSR1 to interrupt waiting for control events
        signal(SIGUSR1, _ignore)

        self._thread = Thread(target=self._receiver, name="ctrl-recv", daemon=True)
        self._thread.start()

    def stop(self):
        log.debug(f"ctrl stopping, thread {self._thread.ident}")
        self.stopped = True
        pthread_kill(self._thread.ident, SIGUSR1)
        self._thread.join()

    def send(self, data: bytes, direction: USBDirection):
        if direction == USBDirection.OUT:
            self.backend.device.ep0_read(data)
        else:
            self.backend.device.ep0_write(data)

    def _receiver(self):
        while not self.stopped:
            try:
                event = self.backend.device.event_fetch(bytes(usb_ctrlrequest.sizeof()))
            except InterruptedError:
                continue

            if event is not None:
                self.backend.queue.put(event)

        log.debug("ctrl-recv done")


class EndpointHandler:
    ep: USBEndpoint
    backend: RawGadgetBackend

    # We could validate the endpoint descriptor against the UDC
    # endpoint capabilities and the selected USB device speed.
    # This will, however, limit the ability to emulate devices
    # that do not strictly follow the USB specifications;
    # some UDCs unofficially support this. As having this ability
    # might be useful for fuzzing, use the endpoint descriptor as
    # is. As a trade off, this might lead to unpredictable errors
    # during the device emulation.
    def __init__(self, ep, backend):
        self.ep = ep
        self.backend = backend
        self.stopped = False

        self._handle = self.backend.device.ep_enable(ep.get_descriptor())
        log.debug(f"enable {ep} ({ep.address}) handle={self._handle}")

    def stop(self):
        log.debug(f"ep-{self.ep.number} stopping")
        self.stopped = True
        try:
            self.backend.device.ep_disable(self._handle)
        except Exception as e:
            log.warning(f"disable {self.ep}: {e}")


class EndpointOutHandler(EndpointHandler):
    """Read OUT transfers from the host and report them to the core Facedancer code."""

    def __init__(self, ep, backend):
        super().__init__(ep, backend)
        self._thread = Thread(
            target=self._receiver, name=f"ep-{self.ep.number}", daemon=True
        )
        self._thread.start()

    def stop(self):
        super().stop()
        self._thread.join()

    def _receiver(self):
        while not self.stopped:
            try:
                data = self.backend.device.ep_read(
                    self._handle, self.ep.max_packet_size
                )
            except BrokenPipeError:
                continue

            if data is not None:
                event = EpReadEvent(ep=self.ep, handler=self, data=data)
                self.backend.queue.put(event)

        log.debug(f"ep-{self.ep.number} stopped")


INTERVAL_MIN_MS = 100


class EndpointInHandler(EndpointHandler):
    """Read IN transfers from the core Facedancer code and send to the host."""

    def __init__(self, ep, backend):
        super().__init__(ep, backend)

        self._thread = Thread(
            target=self._receiver,
            name=f"ep-{self.ep.number}-recv",
            daemon=True,
        )
        self._thread.start()

    def stop(self):
        super().stop()
        self._thread.join()

    def send(self, data):
        if self.backend.verbose > 3:
            log.debug(f"ep-{self.ep.number} write {data.hex(' ', -2)}")
        self.backend.device.ep_write(self._handle, data)

    def _receiver(self):
        """Read data from device.

        The proxy will call backend.send_on_endpoint()
        which will call self.send().
        """
        while not self.stopped:
            # The interrupt endpoint interval could be 1ms, and polling 1000
            # times a second for something we can just block on is too noisy.
            if self.ep.interval < INTERVAL_MIN_MS:
                self.ep.interval = INTERVAL_MIN_MS

            self.backend.connected_device.handle_data_requested(self.ep)

        log.debug(f"ep-{self.ep.number}-recv stopped")
