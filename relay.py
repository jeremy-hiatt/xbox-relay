import asyncio
import argparse
import logging
import queue
import threading

from scapy.layers import inet, l2
import scapy.packet
import scapy.sendrecv
import uvloop
import websockets


MAC_LENGTH = 17
MAX_BACKOFF = 16


OUI_PREFIX_LENGTH = 8
XBOX_OUI_PREFIXES = {
  '30:59:b7',
  '60:45:bd',
}


log = logging.getLogger(__name__)


class WebSocketTunnel:

  def __init__(self, peer_address, outbox_queue, inbox_queue):
    self._peer_address = peer_address
    self._outbox_queue = outbox_queue
    self._inbox_queue = inbox_queue
    self._client_task = None
    self._server = None
    self._active_senders = 0

  async def start(self):
    host, port = self._peer_address
    if host == "0.0.0.0":
      log.info("Starting in server mode listening on port %s!", port)
      self._server = await websockets.serve(self._communicate, port=port)
    else:
      peer_uri = "ws://{}:{}".format(host, port)
      self._client_task = asyncio.ensure_future(self._connect_to_server(peer_uri))

  async def _connect_to_server(self, peer_uri):
    backoff = 1
    while True:
      try:
        log.info("Opening connection to %s", peer_uri)
        websocket = None
        async with websockets.connect(peer_uri) as websocket:
          log.info("Connected to %s", peer_uri)
          backoff = 1
          await self._communicate(websocket)
      except asyncio.CancelledError:
        log.info("Shutting down!")
        await websocket.close()
        break
      except Exception:
        log.exception("Connection attempt failed!")
        backoff = min(MAX_BACKOFF, backoff * 2)
        log.info("Sleeping %s second(s) before retry.", backoff)
        await asyncio.sleep(backoff)
    log.info("Client task complete!")

  async def close(self):
    if self._server:
      self._server.close()
      await self._server.wait_closed()
      self._server = None

    if self._client_task:
      self._client_task.cancel()
      await self._client_task
      self._client_task = None

  def add_to_tunnel_queue(self, payload):
    if not self._active_senders:
      log.warning("No active connection; can't forward payload.")
      return

    self._outbox_queue.put_nowait(payload)

  async def _consume_inbound(self, websocket):
    async for payload in websocket:
      self._inbox_queue.put_nowait(payload)

  async def _produce_outbound(self, websocket):
    self._active_senders += 1
    try:
      while True:
        payload = await self._outbox_queue.get()
        await websocket.send(payload)
    finally:
      self._active_senders -= 1

  async def _communicate(self, websocket, *args):
    consumer = asyncio.ensure_future(self._consume_inbound(websocket))
    producer = asyncio.ensure_future(self._produce_outbound(websocket))
    try:
      done, pending = await asyncio.wait(
          [consumer, producer],
          return_when=asyncio.FIRST_COMPLETED,
      )
    except asyncio.CancelledError:
      for task in (consumer, producer):
        task.cancel()

      log.info("Cancelled!")
      raise

    for task in pending:
      task.cancel()


class L2Rebroadcaster(threading.Thread):

  def __init__(self, iface, outbox_queue):
    super().__init__()
    self._iface = iface
    self._outbox_queue = outbox_queue
    self._addresses_spoofed = set()

  def is_spoofed_address(self, mac_address):
    return mac_address in self._addresses_spoofed

  def run(self):
    while True:
      payload = self._outbox_queue.get()
      if payload is None:
        log.info("Exiting rebroadcaster task.")
        break

      try:
        packet = l2.Ether(payload)
        log.debug("Rebroadcasting packet %r", packet)
        self._addresses_spoofed.add(packet.src)
        scapy.sendrecv.sendp(packet, iface=self._iface, verbose=False)
      except Exception:
        log.exception("Failed to send packet!")


class L2Forwarder:

  def __init__(self, loop, tunnel, rebroadcaster):
    self._loop = loop
    self._tunnel = tunnel
    self._rebroadcaster = rebroadcaster
    self._local_mac_address = None

  def sniff_and_forward(self, packet):
    if not self._local_mac_address and packet.dst == 'ff:ff:ff:ff:ff:ff':
      if (not self._rebroadcaster.is_spoofed_address(packet.src) and
          packet.src[:OUI_PREFIX_LENGTH] in XBOX_OUI_PREFIXES):
        log.info("Discovered XBox on local network with MAC %s!", packet.src)
        self._local_mac_address = packet.src

    if self._local_mac_address and self._local_mac_address == packet.src:
      log.debug("Got packet needing forward: %r!", packet)
      self._loop.call_soon_threadsafe(self._tunnel.add_to_tunnel_queue, bytes(packet))
    else:
      log.debug("Ignoring packet from %s", packet.src)


def main(peer_address, listen_interface, capture_filter):
  loop = asyncio.get_event_loop()
  send_to_remote_peer_async_queue = asyncio.Queue()
  send_to_local_xbox_queue = queue.Queue()

  local_mac_address = None

  tunnel = WebSocketTunnel(
      peer_address=peer_address,
      outbox_queue=send_to_remote_peer_async_queue,
      inbox_queue=send_to_local_xbox_queue,
  )

  rebroadcaster = L2Rebroadcaster(
      iface=listen_interface,
      outbox_queue=send_to_local_xbox_queue,
  )
  rebroadcaster.start()

  forwarder = L2Forwarder(loop=loop, tunnel=tunnel, rebroadcaster=rebroadcaster)


  sniffer = scapy.sendrecv.AsyncSniffer(iface=listen_interface,
                                       store=False,
                                       prn=forwarder.sniff_and_forward,
                                       filter=capture_filter)
  log.info("Starting capture on interface %s with filter '%s'", listen_interface, capture_filter)
  sniffer.start()

  loop.run_until_complete(tunnel.start())
  try:
    loop.run_forever()
  except KeyboardInterrupt:
    pass

  loop.run_until_complete(tunnel.close())
  sniffer.stop()
  send_to_local_xbox_queue.put(None)
  rebroadcaster.join()


parser = argparse.ArgumentParser(description='Relay XBox packets.')
parser.add_argument('-i', '--interface',
                    required=True,
                    help="BSD interface name on which to handle XBox packets")

parser.add_argument('-p', '--peer-host',
                    default="0.0.0.0",
                    help="Peer host to which to connect. Use 0.0.0.0 for server mode")

parser.add_argument('-l', '--listen-port',
                    type=int,
                    default=6715,
                    help="Port for WebSocket server")
parser.add_argument("-v", "--verbose",
                    action='count',
                    help="Verbosity level (can be specified multiple times")

parser.add_argument('-F', '--filter',
                    default=None,
                    help="Custom BPF filter")


args = parser.parse_args()
log_level = logging.WARNING
for verbosity in range(args.verbose or 0):
  if log_level > logging.DEBUG:
    log_level -= (logging.ERROR - logging.WARNING)

logging.basicConfig(level=log_level)


uvloop.install()
main(
    peer_address=(args.peer_host, args.listen_port),
    listen_interface=args.interface,
    capture_filter=args.filter or 'udp port 3074',
)

