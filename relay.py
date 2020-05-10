import asyncio
import logging
import queue
import threading

from scapy.layers import inet, l2
import scapy.packet
import scapy.sendrecv


MAC_LENGTH = 17
MAX_BACKOFF = 16


OUI_PREFIX_LENGTH = 8
XBOX_OUI_PREFIXES = {
  '30:59:b7',
  '60:45:bd',
}
L2_BROADCAST = "ff:ff:ff:ff:ff:ff"

log = logging.getLogger(__name__)


class DatagramTunnel:

  def __init__(self, loop, local_address, peer_addresses, inbox_queue, outbox_queue):
    self._loop = loop
    self._local_address = local_address
    self._inbox_queue = inbox_queue
    self._outbox_queue = outbox_queue
    self._peer_addresses = peer_addresses
    self._transport = None
    self._outbox_task = None
    self._remote_mac_to_forwarder_addr = {}

  async def start(self):
    self._transport, _ = await self._loop.create_datagram_endpoint(
        lambda: self,
        local_addr=self._local_address,
        reuse_port=True,
    )
    self._outbox_task = asyncio.ensure_future(self._process_outbox())

  async def close(self):
    self._transport.close()

  def connection_made(self, transport):
    pass

  def datagram_received(self, data, addr):
    try:
      packet = l2.Ether(data)
    except Exception as e:
      log.error("Failed to decode packet from %s: %r", addr, e)
      return

    if packet.src not in self._remote_mac_to_forwarder_addr:
      self._remote_mac_to_forwarder_addr[packet.src] = addr
      log.info("MAC %s is forwarded by %s", packet.src, addr)

    self._inbox_queue.put_nowait(packet)

  async def _process_outbox(self):
    while True:
      payload, dest_addr = await self._outbox_queue.get()
      log.debug("Got payload %s for dest addr %s", payload, dest_addr)
      if dest_addr == L2_BROADCAST:
        targets = self._peer_addresses
      else:
        forwarder_addr = self._remote_mac_to_forwarder_addr.get(dest_addr)
        targets = [forwarder_addr] if forwarder_addr else []

      if not targets:
        log.warning("Not sure where to send packet destined for %s", dest_addr)
        return

      if len(payload) > 1400:
        log.warning("Payload of length %d may exceed MTU!", len(payload))

      for address in targets:
        log.debug("Sending to %s", address)
        try:
          self._transport.sendto(payload, address)
        except Exception as e:
          log.error("Failed to deliver packet: %r", e)

  def connection_lost(self, _):
    if self._outbox_task:
      self._outbox_task.cancel()
      self._outbox_task = None

  def add_to_tunnel_queue(self, payload):
    self._outbox_queue.put_nowait(payload)


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
      packet = self._outbox_queue.get()
      if packet is None:
        log.info("Exiting rebroadcaster task.")
        break

      try:
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
      self._loop.call_soon_threadsafe(self._tunnel.add_to_tunnel_queue,
                                      (bytes(packet), packet.dst))
    else:
      log.debug("Ignoring packet from %s", packet.src)


def main(local_address, peer_addresses, listen_interface, capture_filter):
  loop = asyncio.get_event_loop()
  send_to_remote_peers_async_queue = asyncio.Queue()
  send_to_local_xbox_queue = queue.Queue()

  tunnel = DatagramTunnel(
      loop=loop,
      local_address=local_address,
      peer_addresses=peer_addresses,
      outbox_queue=send_to_remote_peers_async_queue,
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


if __name__ == "__main__":
  import argparse
  import sys

  import uvloop

  parser = argparse.ArgumentParser(description='Relay XBox packets.')
  parser.add_argument('-i', '--interface',
                      required=True,
                      help="BSD interface name on which to handle XBox packets")

  parser.add_argument('-p', '--peer-host',
                      action='append',
                      help="Peer host to which to forward packets.")

  parser.add_argument('-l', '--listen-port',
                      type=int,
                      default=6715,
                      help="Port for listen server")
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


  peer_addresses = []
  if not args.peer_host:
    log.error("Must specify at least one peer!")
    sys.exit(1)
  for peer_host in args.peer_host:
    port = args.listen_port
    host, *maybe_port = peer_host.split(":", 1)
    if maybe_port:
      port = int(maybe_port[0])
    peer_addresses.append((host, port))


  uvloop.install()
  main(
      local_address=("0.0.0.0", args.listen_port),
      peer_addresses=peer_addresses,
      listen_interface=args.interface,
      capture_filter=args.filter or 'udp port 3074',
  )

