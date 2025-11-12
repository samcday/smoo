# smoo

A userspace implementation of "reverse USB Mass Storage". That is, the host provides the data to the device.

There's not much to see here yet, besides an extremely hacked together prototype that will probably crash your computer and eat your babies.

## Use case?

This is being implemented to make it possible for a host device to serve up a root FS to a live booted mobile device via USB.

Prior art for this exists with the ["pmOS netboot" feature](https://wiki.postmarketos.org/wiki/Netboot), however with smoo it will be possible to achieve this without NBD (and indeed, without any networking stack at all).

## The name?

USB Mass Storage is frequently referred to as "UMS". UMS backwards is SMU. That sounds like smoo. Yes, I know I suck at naming things.

## Development

### Project structure

 * `apps/smoo-gadget-cli` brings up the ublk device and USB gadget function that backs it
 * `apps/smoo-host-cli` finds a connected smoo gadget and serves I/O requests using a specified file
