import asyncio

from connection_protocols import ClientProtocol

async def main():
    print('Server up')
    loop = asyncio.get_running_loop()

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: ClientProtocol(),
        local_addr=('127.0.0.1', 8053)
    )

    try:
        await asyncio.Future() # Keep the server waiting forever
    except asyncio.CancelledError:
        pass
    finally:
        print("Server down")
        transport.close()

if __name__ == "__main__":
    asyncio.run(main())