import asyncio

from connection_protocols import ServerProtocol

async def main():
    print('Server up')
    loop = asyncio.get_running_loop()

    # Binds to port and creates ServerProtocol to service clients
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: ServerProtocol(),
        local_addr=('127.0.0.1', 8053)
    )

    try:
        await asyncio.Future() # Keep the server waiting forever
        
    except asyncio.CancelledError: # Shut the server down cleanly with keyboard interrupt
        pass

    finally:
        print("Server down")
        transport.close()

if __name__ == "__main__":
    asyncio.run(main())